using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Security;
using System.Xml;
using SAML2.Bindings;
using SAML2.Config;
using SAML2.Properties;
using SAML2.Schema.Metadata;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using Saml2.Properties;

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
            }
            catch (Exception e)
            {
                Logger.Error(e.Message, e);
            }
        }

        #region Private methods - Handlers

        /// <summary>
        /// Handles executing the logout.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="idpInitiated">if set to <c>true</c> [idp initiated].</param>
        private void DoLogout(HttpContext context, bool idpInitiated = false)
        {
            Logger.Debug("Processing Logout request and executing Actions.");
            foreach (var action in Actions.Actions.GetActions())
            {
                Logger.DebugFormat("{0}.{1} called", action.GetType(), "LogoutAction()");

                action.LogoutAction(this, context, idpInitiated);

                Logger.DebugFormat("{0}.{1} finished", action.GetType(), "LogoutAction()");
            }
        }

        /// <summary>
        /// Handles the artifact.
        /// </summary>
        /// <param name="context">The context.</param>
        private void HandleArtifact(HttpContext context)
        {
            Logger.Debug("Resolving HTTP SAML artifact.");

            var builder = new HttpArtifactBindingBuilder(context);
            var inputStream = builder.ResolveArtifact();

            HandleSoap(context, inputStream);
        }

        /// <summary>
        /// Handles the SOAP message.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="inputStream">The input stream.</param>
        private void HandleSoap(HttpContext context, Stream inputStream)
        {
            Logger.DebugFormat("SP initiated SOAP based Logout.");

            var parser = new HttpArtifactBindingParser(inputStream);
            var builder = new HttpArtifactBindingBuilder(context);
            var config = Saml2Config.GetConfig();

            var idp = RetrieveIDPConfiguration(parser.Issuer);
            
            if (parser.IsArtifactResolve)
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
            else if (parser.IsArtifactResponse)
            {
                Logger.Debug(Tracing.ArtifactResponseIn);

                var status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    Logger.ErrorFormat("Unexpected status code for artifact response: {0}, expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage);
                    HandleError(context, status);
                    return;
                }

                if (parser.ArtifactResponse.Any.LocalName == LogoutRequest.ElementName)
                {
                    Logger.DebugFormat(Tracing.LogoutRequest, parser.ArtifactResponse.Any.OuterXml);

                    var req = Serialization.DeserializeFromXmlString<LogoutRequest>(parser.ArtifactResponse.Any.OuterXml);

                    //Send logoutresponse via artifact
                    var response = new Saml20LogoutResponse
                                       {
                                           Issuer = config.ServiceProvider.Id,
                                           StatusCode = Saml20Constants.StatusCodes.Success,
                                           InResponseTo = req.ID
                                       };

                    var endpoint = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());
                    var destination = DetermineEndpointConfiguration(BindingType.Redirect, endpoint.Endpoints.LogoutEndpoint, endpoint.Metadata.SLOEndpoints());

                    builder.RedirectFromLogout(destination, response);
                }
                else if (parser.ArtifactResponse.Any.LocalName == LogoutResponse.ElementName)
                {
                    DoLogout(context);
                }
                else
                {
                    Logger.ErrorFormat("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage);
                    HandleError(context, string.Format("Unsupported payload message in ArtifactResponse: {0}", parser.ArtifactResponse.Any.LocalName));
                }
            }
            else if (parser.IsLogoutReqest)
            {
                Logger.DebugFormat(Tracing.LogoutRequest, parser.SamlMessage.OuterXml);

                var req = parser.LogoutRequest;
                
                //Build the response object
                var response = new Saml20LogoutResponse
                                   {
                                       Issuer = config.ServiceProvider.Id,
                                       StatusCode = Saml20Constants.StatusCodes.Success,
                                       InResponseTo = req.ID
                                   };
                //response.Destination = destination.Url;

                var doc = response.GetXml();
                XmlSignatureUtils.SignDocument(doc, response.ID);
                if (doc.FirstChild is XmlDeclaration)
                {
                    doc.RemoveChild(doc.FirstChild);
                }
                
                builder.SendResponseMessage(doc.OuterXml);
            }
            else
            {
                var s = parser.GetStatus();
                if (s != null)
                {
                    // TODO: Consider logging here
                    HandleError(context, s);
                }
                else
                {
                    Logger.ErrorFormat("Unsupported SamlMessage element: {0}, msg: {1}", parser.SamlMessageName, parser.SamlMessage);
                    HandleError(context, string.Format("Unsupported SamlMessage element: {0}", parser.SamlMessageName));
                }
            }
        }

        /// <summary>
        /// Handles the request.
        /// </summary>
        /// <param name="context">The context.</param>
        private void HandleRequest(HttpContext context)
        {
            Logger.DebugFormat("Generating Logout SAML Request.");

            //Fetch the endpoint configuration
            var idp = RetrieveIDPConfiguration(context.Session[IDPLoginSessionKey].ToString());
            var destination = DetermineEndpointConfiguration(BindingType.Redirect, idp.Endpoints.LogoutEndpoint, idp.Metadata.SLOEndpoints());

            //Fetch config object
            var config = Saml2Config.GetConfig();

            //Build the response object
            var response = new Saml20LogoutResponse
            {
                Issuer = config.ServiceProvider.Id,
                Destination = destination.Url,
                StatusCode = Saml20Constants.StatusCodes.Success
            };

            var message = string.Empty;

            if (context.Request.RequestType == "GET") // HTTP Redirect binding
            {
                var parser = new HttpRedirectBindingParser(context.Request.Url);
                Logger.DebugFormat("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message);

                var endpoint = config.IdentityProviders.FirstOrDefault(x => x.Id == idp.Id);
                if (endpoint == null || endpoint.Metadata == null)
                {
                    Logger.Error("Cannot find metadata for IDP");
                    HandleError(context, "Cannot find metadata for IDP " + idp.Id);
                    return;
                }

                var metadata = endpoint.Metadata;
                if (!parser.VerifySignature(metadata.GetKeys(KeyTypes.Signing)))
                {
                    Logger.Error("Invalid signature redirect-binding, msg: " + parser.Message);
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }

                message = parser.Message;
            }
            else if (context.Request.RequestType == "POST") // HTTP Post binding
            {
                var parser = new HttpPostBindingParser(context);
                Logger.Debug("Binding: POST, Message: " + parser.Message);

                if (!parser.IsSigned)
                {
                    Logger.Error("Signature not present, msg: " + parser.Message);
                    HandleError(context, Resources.SignatureNotPresent);
                }

                var endpoint = config.IdentityProviders.FirstOrDefault(x => x.Id == idp.Id);
                if (endpoint == null || endpoint.Metadata == null)
                {
                    Logger.Error("Cannot find metadata for IDP");
                    HandleError(context, "Cannot find metadata for IDP " + idp.Id);
                    return;
                }

                var metadata = endpoint.Metadata;

                // handle a logout-request
                if (!parser.CheckSignature(metadata.GetKeys(KeyTypes.Signing)))
                {
                    Logger.Error("Invalid signature post-binding, msg: " + parser.Message);
                    HandleError(context, Resources.SignatureInvalid);
                }

                message = parser.Message;
            }
            else
            {
                //Error: We don't support HEAD, PUT, CONNECT, TRACE, DELETE and OPTIONS
                HandleError(context, Resources.UnsupportedRequestTypeFormat(context.Request.RequestType));
            }

            Logger.Debug(message);

            // Log the user out locally
            DoLogout(context, true);

            var req = Serialization.DeserializeFromXmlString<LogoutRequest>(message);

            response.InResponseTo = req.ID;

            // Respond using redirect binding
            if (destination.Binding == BindingType.Redirect)
            {
                var builder = new HttpRedirectBindingBuilder
                {
                    RelayState = context.Request.Params["RelayState"],
                    Response = response.GetXml().OuterXml,
                    SigningKey = Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate().PrivateKey
                };
                context.Response.Redirect(destination.Url + "?" + builder.ToQuery(), true);
                return;
            }

            //Respond using post binding
            if (destination.Binding == BindingType.Post)
            {
                var builder = new HttpPostBindingBuilder(destination)
                {
                    Action = SAMLAction.SAMLResponse
                };

                var responseDocument = response.GetXml();
                XmlSignatureUtils.SignDocument(responseDocument, response.ID);
                builder.Response = responseDocument.OuterXml;
                builder.RelayState = context.Request.Params["RelayState"];
                builder.GetPage().ProcessRequest(context);
            }
        }
        
        /// <summary>
        /// Handles the response.
        /// </summary>
        /// <param name="context">The context.</param>
        private void HandleResponse(HttpContext context)
        {
            Logger.DebugFormat("Processing SAML Response.");

            var message = string.Empty;

            if (context.Request.RequestType == "GET")
            {
                var parser = new HttpRedirectBindingParser(context.Request.Url);
                var response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                Logger.DebugFormat("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message);

                var idp = RetrieveIDPConfiguration(response.Issuer.Value);
                
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
            }
            else if (context.Request.RequestType == "POST")
            {
                var parser = new HttpPostBindingParser(context);
                Logger.Debug("Binding: POST, Message: " + parser.Message);

                var response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                var idp = RetrieveIDPConfiguration(response.Issuer.Value);

                if (idp.Metadata == null)
                {
                    Logger.ErrorFormat("No IDP metadata, unknown IDP, response: {0}", parser.Message);
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.IsSigned)
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
            }
            else
            {
                Logger.ErrorFormat("Unsupported request type format, type: {0}", context.Request.RequestType);
                HandleError(context, Resources.UnsupportedRequestTypeFormat(context.Request.RequestType));
            }

            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.LoadXml(message);

            var statElem = (XmlElement)doc.GetElementsByTagName(Status.ElementName, Saml20Constants.PROTOCOL)[0];
            var status = Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
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

        /// <summary>
        /// Transfers the client.
        /// </summary>
        /// <param name="idp">The idp.</param>
        /// <param name="context">The context.</param>
        private void TransferClient(IdentityProviderElement idp, HttpContext context)
        {
            var request = Saml20LogoutRequest.GetDefault();

            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            var destination = DetermineEndpointConfiguration(BindingType.Redirect, idp.Endpoints.LogoutEndpoint, idp.Metadata.SLOEndpoints());
            request.Destination = destination.Url;

            var nameIdFormat = context.Session[IDPNameIdFormat].ToString();
            request.SubjectToLogOut.Format = nameIdFormat;

            // Handle POST binding
            if (destination.Binding == BindingType.Post)
            {
                var builder = new HttpPostBindingBuilder(destination);
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();
                var requestDocument = request.GetXml();
                XmlSignatureUtils.SignDocument(requestDocument, request.ID);
                builder.Request = requestDocument.OuterXml;

                Logger.DebugFormat(Tracing.SendLogoutRequest, "POST", idp.Id, requestDocument.OuterXml);

                builder.GetPage().ProcessRequest(context);
                context.Response.End();
                return;
            }

            // Handle Redirect binding
            if (destination.Binding == BindingType.Redirect)
            {
                var builder = new HttpRedirectBindingBuilder
                {
                    Request = request.GetXml().OuterXml,
                    SigningKey = Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate().PrivateKey
                };

                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();

                var redirectUrl = destination.Url + "?" + builder.ToQuery();

                Logger.DebugFormat(Tracing.SendLogoutRequest, "REDIRECT", idp.Id, redirectUrl);

                context.Response.Redirect(redirectUrl, true);
                return;
            }

            // Handle Artifact binding
            if (destination.Binding == BindingType.Artifact)
            {
                Logger.DebugFormat(Tracing.SendLogoutRequest, "ARTIFACT", idp.Id, string.Empty);

                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = context.Session[IDPNameId].ToString();
                request.SessionIndex = context.Session[IDPSessionIdKey].ToString();

                var builder = new HttpArtifactBindingBuilder(context);
                builder.RedirectFromLogout(destination, request, Guid.NewGuid().ToString("N"));
            }

            Logger.Error(Resources.BindingError);
            HandleError(context, Resources.BindingError);
        }

        #endregion

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
                //Some IDP's are known to fail to set an actual value in the SOAPAction header
                //so we just check for the existence of the header field.
                if (Array.Exists(context.Request.Headers.AllKeys, s => s == SoapConstants.SoapAction))
                {
                    HandleSoap(context, context.Request.InputStream);
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
                else if (!string.IsNullOrEmpty(context.Request.Params["SAMLRequest"]))
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
            }
            catch (Exception e)
            {
                //ThreadAbortException is thrown by response.Redirect so don't worry about it
                if (e is ThreadAbortException)
                {
                    throw;
                }

                Logger.Error(e.Message, e);
                HandleError(context, e.Message);
            }
        }

        #endregion
    }
}
