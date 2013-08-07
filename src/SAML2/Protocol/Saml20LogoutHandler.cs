using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Security;
using System.Xml;
using SAML2.Bindings;
using SAML2.Config;
using SAML2.Logging;
using SAML2.Properties;
using SAML2.Schema.Metadata;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using Saml2.Properties;
using SAML2.Actions;

namespace SAML2.Protocol
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
                RedirectUrl = Saml2Config.GetConfig().ServiceProvider.Endpoints.LogoutEndpoint.RedirectUrl;
                ErrorBehaviour = Saml2Config.GetConfig().ServiceProvider.Endpoints.LogoutEndpoint.ErrorBehaviour.ToString();
            }
            catch (Exception e)
            {
                Logger.Error(e.Message, e);
            }
        }

        #region IHttpHandler related 

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Logger.Debug("Logout handler called.");
            
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
                    IdentityProviderElement idpEndpoint = null;
                    //context.Session[IDPLoginSessionKey] may be null if IIS has been restarted
                    if (context.Session[IDPSessionIdKey] != null)
                    {
                        idpEndpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());
                    }

                    if (idpEndpoint == null)
                    {
                        // TODO: Reconsider how to accomplish this.
                        context.User = null;
                        FormsAuthentication.SignOut();

                        Logger.Error(Resources.UnknownLoginIDP);
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
            Logger.Debug("Resolving HTTP SAML artifact.");

            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            Stream inputStream = builder.ResolveArtifact();

            HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
        {
            Logger.DebugFormat("SP initiated SOAP based Logout.");

            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            var config = Saml2Config.GetConfig();

            IdentityProviderElement idp = RetrieveIDPConfiguration(parser.Issuer);
            
            if (parser.IsArtifactResolve())
            {
                Logger.Debug(Tracing.ArtifactResolveIn);

                if (!parser.CheckSamlMessageSignature(idp.Metadata.Keys))
                {
                    Logger.ErrorFormat("Signature could not be verified during artifact resolve, msg: " + parser.SamlMessage);
                    HandleError(context, "Invalid Saml message signature");
                }

                Logger.DebugFormat("Artifact resolve for assertion id: {0}, msg: {1}", parser.ArtifactResolve.ID, parser.SamlMessage);
                builder.RespondToArtifactResolve(parser.ArtifactResolve);
            }
            else if (parser.IsArtifactResponse())
            {
                Logger.Debug(Tracing.ArtifactResponseIn);

                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    Logger.ErrorFormat("Unexpected status code for artifact response: {0}, expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage);
                    HandleError(context, status);
                    return;
                }

                if (parser.ArtifactResponse.Any.LocalName == LogoutRequest.ELEMENT_NAME)
                {
                    Logger.DebugFormat(Tracing.LogoutRequest, parser.ArtifactResponse.Any.OuterXml);

                    //Send logoutresponse via artifact
                    Saml20LogoutResponse response = new Saml20LogoutResponse();
                    response.Issuer = config.ServiceProvider.Id;
                    LogoutRequest req = Serialization.DeserializeFromXmlString<LogoutRequest>(parser.ArtifactResponse.Any.OuterXml);
                    response.StatusCode = Saml20Constants.StatusCodes.Success;
                    response.InResponseTo = req.ID;
                    IdentityProviderElement endpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());
                    IdentityProviderEndpointElement destination =
                        DetermineEndpointConfiguration(BindingType.Redirect, endpoint.Endpoints.LogOffEndpoint, endpoint.Metadata.SLOEndpoints());

                    builder.RedirectFromLogout(destination, response);
                }else if(parser.ArtifactResponse.Any.LocalName == LogoutResponse.ELEMENT_NAME)
                {
                    DoLogout(context);
                }
                else
                {
                    Logger.ErrorFormat("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage);
                    HandleError(context, string.Format("Unsupported payload message in ArtifactResponse: {0}", parser.ArtifactResponse.Any.LocalName));
                }
            }
            else if(parser.IsLogoutReqest())
            {
                Logger.DebugFormat(Tracing.LogoutRequest, parser.SamlMessage.OuterXml);

                LogoutRequest req = parser.LogoutRequest;
                
                //Build the response object
                Saml20LogoutResponse response = new Saml20LogoutResponse();
                response.Issuer = config.ServiceProvider.Id;
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


        private void TransferClient(IdentityProviderElement endpoint, HttpContext context)
        {
            Saml20LogoutRequest request = Saml20LogoutRequest.GetDefault();
            
            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            IdentityProviderEndpointElement destination =
                DetermineEndpointConfiguration(BindingType.Redirect, endpoint.Endpoints.LogOffEndpoint, endpoint.Metadata.SLOEndpoints());
            
            request.Destination = destination.Url;

            string nameIdFormat = context.Session[IDPNameIdFormat].ToString();
            request.SubjectToLogOut.Format = nameIdFormat;
            
            if (destination.Binding == BindingType.Post)
            {
                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                 request.SessionIndex = context.Session[IDPSessionIdKey].ToString();
                XmlDocument requestDocument = request.GetXml();
                XmlSignatureUtils.SignDocument(requestDocument, request.ID);
                builder.Request = requestDocument.OuterXml;

                Logger.DebugFormat(Tracing.SendLogoutRequest, "POST", endpoint.Id, requestDocument.OuterXml);

                builder.GetPage().ProcessRequest(context);
                context.Response.End();
                return;
            }

            if(destination.Binding == BindingType.Redirect)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate().PrivateKey;
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();
                builder.Request = request.GetXml().OuterXml;
                
                string redirectUrl = destination.Url + "?" + builder.ToQuery();

                Logger.DebugFormat(Tracing.SendLogoutRequest, "REDIRECT", endpoint.Id, redirectUrl);

                context.Response.Redirect(redirectUrl, true);
                return;
            }

            if(destination.Binding == BindingType.Artifact)
            {
                Logger.DebugFormat(Tracing.SendLogoutRequest, "ARTIFACT", endpoint.Id, string.Empty);

                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();

                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
                builder.RedirectFromLogout(destination, request, Guid.NewGuid().ToString("N"));
            }

            Logger.Error(Resources.BindingError);
            HandleError(context, Resources.BindingError);
        }
        
        #endregion

        #region SAMLResponse related

        private void HandleResponse(HttpContext context)
        {
            Logger.DebugFormat("Processing SAML Response.");

            string message = string.Empty;

            if(context.Request.RequestType == "GET")
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                Logger.DebugFormat("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message);

                IdentityProviderElement idp = RetrieveIDPConfiguration(response.Issuer.Value);
                
                if (idp.Metadata == null)
                {
                    Logger.ErrorFormat("No IDP metadata, unknown IDP, response: {0}", parser.Message);
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.VerifySignature(idp.Metadata.Keys))
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

                IdentityProviderElement idp = RetrieveIDPConfiguration(response.Issuer.Value);

                if (idp.Metadata == null)
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
                if (!parser.CheckSignature(idp.Metadata.Keys))
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

            XmlElement statElem = (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            Status status = Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);

            if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
            {
                Logger.ErrorFormat("Unexpected status code: {0}, msg: {1}", status.StatusCode.Value, message);
                HandleError(context, status);
                return;
            }

            Logger.Debug("SAML Response Assertion validated succesfully.");

            //Log the user out locally
            DoLogout(context);
        }

        #endregion

        #region SAMLRequest related

        private void HandleRequest(HttpContext context)
        {
            Logger.DebugFormat("Generating Logout SAML Request.");

            //Fetch the endpoint configuration
            IdentityProviderElement idpEndpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());

            IdentityProviderEndpointElement destination =
                DetermineEndpointConfiguration(BindingType.Redirect, idpEndpoint.Endpoints.LogOffEndpoint, idpEndpoint.Metadata.SLOEndpoints());

            //Fetch config object
            var config = Saml2Config.GetConfig();
                        
            //Build the response object
            Saml20LogoutResponse response = new Saml20LogoutResponse();
            response.Issuer = config.ServiceProvider.Id;
            response.Destination = destination.Url;
            response.StatusCode = Saml20Constants.StatusCodes.Success;

            string message = string.Empty;

            if(context.Request.RequestType == "GET") // HTTP Redirect binding
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                Logger.DebugFormat("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message);
                
                IdentityProviderElement endpoint = config.IdentityProviders.FirstOrDefault(x => x.Id == idpEndpoint.Id);

                if (endpoint.Metadata == null)
                {
                    Logger.Error("Cannot find metadata for IdP");
                    HandleError(context, "Cannot find metadata for IdP " + idpEndpoint.Id);
                    return;
                }

                Saml20MetadataDocument metadata = endpoint.Metadata;

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

                IdentityProviderElement endpoint = config.IdentityProviders.FirstOrDefault(x => x.Id == idpEndpoint.Id);
                if (endpoint.Metadata == null)
                {
                    Logger.Error("Cannot find metadata for IdP");
                    HandleError(context, "Cannot find metadata for IdP " + idpEndpoint.Id);
                    return;
                }

                Saml20MetadataDocument metadata = endpoint.Metadata;

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
            if(destination.Binding == BindingType.Redirect)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.RelayState = context.Request.Params["RelayState"];
                builder.Response = response.GetXml().OuterXml;
                builder.signingKey = Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate().PrivateKey;
                string s = destination.Url + "?" + builder.ToQuery();
                context.Response.Redirect(s, true);
                return;
            }

            //Respond using post binding
            if (destination.Binding == BindingType.Post)
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
            Logger.Debug("Processing Logout request and executing Actions.");
            foreach (IAction action in Actions.Actions.GetActions())
            {
                Logger.DebugFormat("{0}.{1} called", action.GetType(), "LogoutAction()");
                
                action.LogoutAction(this, context, IdPInitiated);

                Logger.DebugFormat("{0}.{1} finished", action.GetType(), "LogoutAction()");
            }
        }
                
        #endregion
    }
}
