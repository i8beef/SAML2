using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Web;
using System.Web.Security;
using System.Xml;
using SAML2.Bindings;
using SAML2.config;
using SAML2.Logging;
using SAML2.Properties;
using SAML2.Schema.Metadata;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using Saml2.Properties;
using Trace=SAML2.Utils.Trace;
using SAML2.Actions;

namespace SAML2.protocol
{
    /// <summary>
    /// Handles logout for all SAML bindings.
    /// </summary>
    public class Saml20LogoutHandler : Saml20AbstractEndpointHandler
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20LogoutHandler"/> class.
        /// </summary>
        public Saml20LogoutHandler()
        {
            // Read the proper redirect url from config
            try
            {
                RedirectUrl = SAML20FederationConfig.GetConfig().ServiceProvider.LogoutEndpoint.RedirectUrl;
                ErrorBehaviour = SAML20FederationConfig.GetConfig().ServiceProvider.LogoutEndpoint.ErrorBehaviour.ToString();
            }
            catch (Exception e)
            {
                if (Trace.ShouldTrace(TraceEventType.Error))
                    Trace.TraceData(TraceEventType.Error, e.ToString());
            }
        }

        #region IHttpHandler related 

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "Handle()");
            
            try
            {
                //Some IdP's are known to fail to set an actual value in the SOAPAction header
                //so we just check for the existence of the header field.
                if (Array.Exists(context.Request.Headers.AllKeys, delegate(string s) { return s == SOAPConstants.SOAPAction; }))
                {
                    HandleSOAP(context, context.Request.InputStream);
                    return;
                }

                if (!string.IsNullOrEmpty(context.Request.Params["SAMLart"]))
                {
                    HandleArtifact(context);
                    return;
                }

                if (!string.IsNullOrEmpty(context.Request.Params["SAMLResponse"]))
                {
                    HandleResponse(context);
                }
                else if(!string.IsNullOrEmpty(context.Request.Params["SAMLRequest"]))
                {
                    HandleRequest(context);
                }
                else
                {
                    IDPEndPoint idpEndpoint = null;
                    //context.Session[IDPLoginSessionKey] may be null if IIS has been restarted
                    if (context.Session[IDPSessionIdKey] != null)
                    {
                        idpEndpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());
                    }

                    if (idpEndpoint == null)
                    {
                        context.User = null;
                        FormsAuthentication.SignOut();
                        HandleError(context, Resources.UnknownLoginIDP);
                    }

                    TransferClient(idpEndpoint, context);
                }
            }catch(Exception e)
            {
                //ThreadAbortException is thrown by response.Redirect so don't worry about it
                if(e is ThreadAbortException)
                    throw;
                    
                HandleError(context, e.Message);
            }
        }
        
        #endregion

        #region SP Initiated logout

        private void HandleArtifact(HttpContext context)
        {
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            Stream inputStream = builder.ResolveArtifact();

            HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
        {
            Trace.TraceMethodCalled(GetType(), "HandleSOAP");

            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            IDPEndPoint idp = RetrieveIDPConfiguration(parser.Issuer);
            
            if (parser.IsArtifactResolve())
            {
                Trace.TraceData(TraceEventType.Information, Tracing.ArtifactResolveIn);

                if (!parser.CheckSamlMessageSignature(idp.metadata.Keys))
                {
                    Logger.ErrorFormat("Signature could not be verified during artifact resolve, msg: " + parser.SamlMessage);
                    HandleError(context, "Invalid Saml message signature");
                }

                Logger.DebugFormat("Artifact resolve for assertion id: {0}, msg: {1}", parser.ArtifactResolve.ID, parser.SamlMessage);
                builder.RespondToArtifactResolve(parser.ArtifactResolve);
            }
            else if (parser.IsArtifactResponse())
            {
                Trace.TraceData(TraceEventType.Information, Tracing.ArtifactResponseIn);

                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    Logger.ErrorFormat("Unexpected status code for artifact response: {0}, expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage);
                    HandleError(context, status);
                    return;
                }

                if (parser.ArtifactResponse.Any.LocalName == LogoutRequest.ELEMENT_NAME)
                {
                    if(Trace.ShouldTrace(TraceEventType.Information))
                        Trace.TraceData(TraceEventType.Information, string.Format(Tracing.LogoutRequest, parser.ArtifactResponse.Any.OuterXml));

                    //Send logoutresponse via artifact
                    Saml20LogoutResponse response = new Saml20LogoutResponse();
                    response.Issuer = config.ServiceProvider.ID;
                    LogoutRequest req = Serialization.DeserializeFromXmlString<LogoutRequest>(parser.ArtifactResponse.Any.OuterXml);
                    response.StatusCode = Saml20Constants.StatusCodes.Success;
                    response.InResponseTo = req.ID;
                    IDPEndPoint endpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());
                    IDPEndPointElement destination =
                        DetermineEndpointConfiguration(SAMLBinding.REDIRECT, endpoint.SLOEndpoint, endpoint.metadata.SLOEndpoints());

                    builder.RedirectFromLogout(destination, response);
                }else if(parser.ArtifactResponse.Any.LocalName == LogoutResponse.ELEMENT_NAME)
                {
                    DoLogout(context);
                }
                else
                {
                    Logger.ErrorFormat("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage);
                    HandleError(context,
                                string.Format("Unsupported payload message in ArtifactResponse: {0}",
                                              parser.ArtifactResponse.Any.LocalName));
                }
            }
            else if(parser.IsLogoutReqest())
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.LogoutRequest, parser.SamlMessage.OuterXml));

                LogoutRequest req = parser.LogoutRequest;
                
                //Build the response object
                Saml20LogoutResponse response = new Saml20LogoutResponse();
                response.Issuer = config.ServiceProvider.ID;
                //response.Destination = destination.Url;
                response.StatusCode = Saml20Constants.StatusCodes.Success;
                response.InResponseTo = req.ID;
                XmlDocument doc = response.GetXml();
                XmlSignatureUtils.SignDocument(doc, response.ID);
                if (doc.FirstChild is XmlDeclaration)
                    doc.RemoveChild(doc.FirstChild);
                
                builder.SendResponseMessage(doc.OuterXml);
                
            }
            else
            {
                Status s = parser.GetStatus();
                if (s != null)
                {
                    HandleError(context, s);
                }
                else
                {
                    Logger.ErrorFormat("Unsupported SamlMessage element: {0}, msg: {1}", parser.SamlMessageName, parser.SamlMessage);
                    HandleError(context, string.Format("Unsupported SamlMessage element: {0}", parser.SamlMessageName));
                }
            }
        }


        private void TransferClient(IDPEndPoint endpoint, HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "TransferClient()");
            
            Saml20LogoutRequest request = Saml20LogoutRequest.GetDefault();
            
            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            IDPEndPointElement destination =
                DetermineEndpointConfiguration(SAMLBinding.REDIRECT, endpoint.SLOEndpoint, endpoint.metadata.SLOEndpoints());
            
            request.Destination = destination.Url;

            string nameIdFormat = context.Session[IDPNameIdFormat].ToString();
            request.SubjectToLogOut.Format = nameIdFormat;
            
            if (destination.Binding == SAMLBinding.POST)
            {
                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                 request.SessionIndex = context.Session[IDPSessionIdKey].ToString();
                XmlDocument requestDocument = request.GetXml();
                XmlSignatureUtils.SignDocument(requestDocument, request.ID);
                builder.Request = requestDocument.OuterXml;

                if(Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "POST", endpoint.Id, requestDocument.OuterXml));

                Logger.Debug("Logout request for POST binding");
                builder.GetPage().ProcessRequest(context);
                context.Response.End();
                return;
            }

            if(destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = FederationConfig.GetConfig().SigningCertificate.GetCertificate().PrivateKey;
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();
                builder.Request = request.GetXml().OuterXml;
                
                string redirectUrl = destination.Url + "?" + builder.ToQuery();

                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "REDIRECT", endpoint.Id, redirectUrl));

                Logger.Debug("Logout request for redirect binding");
                context.Response.Redirect(redirectUrl, true);
                return;
            }

            if(destination.Binding == SAMLBinding.ARTIFACT)
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "ARTIFACT", endpoint.Id, string.Empty));

                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();

                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
                Logger.Debug("Logout request for artifact binding");
                builder.RedirectFromLogout(destination, request, Guid.NewGuid().ToString("N"));
            }

            HandleError(context, Resources.BindingError);
        }
        
        #endregion

        #region SAMLResponse related

        private void HandleResponse(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "HandleResponse()");


            string message = string.Empty;

            if(context.Request.RequestType == "GET")
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                Logger.DebugFormat("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message);

                IDPEndPoint idp = RetrieveIDPConfiguration(response.Issuer.Value);
                
                if (idp.metadata == null)
                {
                    Logger.ErrorFormat("No IDP metadata, unknown IDP, response: {0}", parser.Message);
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.VerifySignature(idp.metadata.Keys))
                {
                    Logger.ErrorFormat("Invalid signature in redirect-binding, response: {0}", parser.Message);
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }

                message = parser.Message;
            }else if(context.Request.RequestType == "POST")
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                Logger.Debug("Binding: POST, Message: " + parser.Message);

                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                IDPEndPoint idp = RetrieveIDPConfiguration(response.Issuer.Value);

                if (idp.metadata == null)
                {
                    Logger.ErrorFormat("No IDP metadata, unknown IDP, response: {0}", parser.Message);
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.IsSigned())
                {
                    Logger.ErrorFormat("Signature not present, response: {0}", parser.Message);
                    HandleError(context, Resources.SignatureNotPresent);
                }

                // signature on final message in logout
                if (!parser.CheckSignature(idp.metadata.Keys))
                {
                    Logger.ErrorFormat("Invalid signature in post-binding, response: {0}", parser.Message);
                    HandleError(context, Resources.SignatureInvalid);
                }

                message = parser.Message;
            }else
            {
                Logger.ErrorFormat("Unsupported request type format, type: {0}", context.Request.RequestType);
                HandleError(context, Resources.UnsupportedRequestTypeFormat(context.Request.RequestType));
            }

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(message);

            XmlElement statElem =
                (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            Status status = Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);

            if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
            {
                Logger.ErrorFormat("Unexpected status code: {0}, msg: {1}", status.StatusCode.Value, message);
                HandleError(context, status);
                return;
            }

            Logger.Debug("Assertion validated succesfully");

            //Log the user out locally
            DoLogout(context);
        }

        #endregion

        #region SAMLRequest related

        private void HandleRequest(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "HandleRequest()");

            //Fetch the endpoint configuration
            IDPEndPoint idpEndpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());

            IDPEndPointElement destination =
                DetermineEndpointConfiguration(SAMLBinding.REDIRECT, idpEndpoint.SLOEndpoint, idpEndpoint.metadata.SLOEndpoints());

            //Fetch config object
            SAML20FederationConfig config = ConfigurationReader.GetConfig<SAML20FederationConfig>();
                        
            //Build the response object
            Saml20LogoutResponse response = new Saml20LogoutResponse();
            response.Issuer = config.ServiceProvider.ID;
            response.Destination = destination.Url;
            response.StatusCode = Saml20Constants.StatusCodes.Success;

            string message = string.Empty;

            if(context.Request.RequestType == "GET") // HTTP Redirect binding
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                Logger.DebugFormat("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message);
                
                IDPEndPoint endpoint = config.FindEndPoint(idpEndpoint.Id);

                if (endpoint.metadata == null)
                {
                    Logger.Error("Cannot find metadata for IdP");
                    HandleError(context, "Cannot find metadata for IdP " + idpEndpoint.Id);
                    return;
                }

                Saml20MetadataDocument metadata = endpoint.metadata;

                if (!parser.VerifySignature(metadata.GetKeys(KeyTypes.signing)))
                {
                    Logger.Error("Invalid signature redirect-binding, msg: " + parser.Message);
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }

                message = parser.Message;
            }
            else if (context.Request.RequestType == "POST") // HTTP Post binding
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                Logger.Debug("Binding: POST, Message: " + parser.Message);

                if (!parser.IsSigned())
                {
                    Logger.Error("Signature not present, msg: " + parser.Message);
                    HandleError(context, Resources.SignatureNotPresent);
                }

                IDPEndPoint endpoint = config.FindEndPoint(idpEndpoint.Id);
                if (endpoint.metadata == null)
                {
                    Logger.Error("Cannot find metadata for IdP");
                    HandleError(context, "Cannot find metadata for IdP " + idpEndpoint.Id);
                    return;
                }

                Saml20MetadataDocument metadata = endpoint.metadata;

                // handle a logout-request
                if (!parser.CheckSignature(metadata.GetKeys(KeyTypes.signing)))
                {
                    Logger.Error("Invalid signature post-binding, msg: " + parser.Message);
                    HandleError(context, Resources.SignatureInvalid);
                }

                message = parser.Message;
            }else
            {
                //Error: We don't support HEAD, PUT, CONNECT, TRACE, DELETE and OPTIONS
                HandleError(context, Resources.UnsupportedRequestTypeFormat(context.Request.RequestType));
            }

            Logger.Debug(message);

            //Log the user out locally
            DoLogout(context, true);

            LogoutRequest req = Serialization.DeserializeFromXmlString<LogoutRequest>(message);

            response.InResponseTo = req.ID;

            //Respond using redirect binding
            if(destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.RelayState = context.Request.Params["RelayState"];
                builder.Response = response.GetXml().OuterXml;
                builder.signingKey = FederationConfig.GetConfig().SigningCertificate.GetCertificate().PrivateKey;
                string s = destination.Url + "?" + builder.ToQuery();
                context.Response.Redirect(s, true);
                return;
            }

            //Respond using post binding
            if (destination.Binding == SAMLBinding.POST)
            {
                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                builder.Action = SAMLAction.SAMLResponse;                                
                XmlDocument responseDocument = response.GetXml();
                XmlSignatureUtils.SignDocument(responseDocument, response.ID);
                builder.Response = responseDocument.OuterXml;
                builder.RelayState = context.Request.Params["RelayState"];
                builder.GetPage().ProcessRequest(context);
                return;
            }
        }

        #endregion

        #region Private utility functions

        private void DoLogout(HttpContext context)
        {
            DoLogout(context, false);
        }

        private void DoLogout(HttpContext context, bool IdPInitiated)
        {
            foreach (IAction action in Actions.Actions.GetActions())
            {
                Trace.TraceMethodCalled(action.GetType(), "LogoutAction()");
                
                action.LogoutAction(this, context, IdPInitiated);

                Trace.TraceMethodDone(action.GetType(), "LogoutAction()");
            }
        }
                
        #endregion
    }
}
