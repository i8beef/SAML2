using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Caching;
using System.Xml;
using SAML2.Bindings;
using SAML2.Config;
using SAML2.Properties;
using SAML2.Protocol.pages;
using SAML2.Schema.Core;
using SAML2.Schema.Metadata;
using SAML2.Schema.Protocol;
using SAML2.Specification;
using SAML2.Utils;
using Saml2.Properties;

namespace SAML2.Protocol
{
    /// <summary>
    /// Implements a Saml 2.0 protocol sign-on endpoint. Handles all SAML bindings.
    /// </summary>
    public class Saml20SignonHandler : Saml20AbstractEndpointHandler
    {
        /// <summary>
        /// Session key used to save the current message id with the purpose of preventing replay attacks
        /// </summary>
        private const string ExpectedInResponseToSessionKey = "ExpectedInResponseTo";

        /// <summary>
        /// The certificate for the endpoint.
        /// </summary>
        private readonly X509Certificate2  _certificate;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20SignonHandler"/> class.
        /// </summary>
        public Saml20SignonHandler()
        {
            _certificate = Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate();

            // Read the proper redirect url from config
            try
            {
                RedirectUrl = Saml2Config.GetConfig().ServiceProvider.Endpoints.SignOnEndpoint.RedirectUrl;
            }
            catch(Exception e)
            {
                Logger.Error(e.Message, e);
            }
        }

        #region Public methods

        /// <summary>
        /// Gets the trusted signers.
        /// </summary>
        /// <param name="keys">The keys.</param>
        /// <param name="ep">The ep.</param>
        /// <returns>List of trusted certificate signers.</returns>
        public static IEnumerable<AsymmetricAlgorithm> GetTrustedSigners(ICollection<KeyDescriptor> keys, IdentityProviderElement ep)
        {
            if (keys == null)
            {
                throw new ArgumentNullException("keys");
            }

            var result = new List<AsymmetricAlgorithm>(keys.Count);
            foreach (var keyDescriptor in keys)
            {
                foreach (KeyInfoClause clause in (KeyInfo)keyDescriptor.KeyInfo)
                {
                    // Check certificate specifications
                    if (clause is KeyInfoX509Data)
                    {
                        var cert = XmlSignatureUtils.GetCertificateFromKeyInfo((KeyInfoX509Data)clause);
                        if (!CertificateSatisfiesSpecifications(ep, cert))
                        {
                            continue;
                        }
                    }

                    var key = XmlSignatureUtils.ExtractKey(clause);
                    result.Add(key);
                }
            }

            return result;
        }

        /// <summary>
        /// Gets the assertion.
        /// </summary>
        /// <param name="el">The el.</param>
        /// <param name="isEncrypted">if set to <c>true</c> [is encrypted].</param>
        /// <returns>The assertion XML.</returns>
        internal static XmlElement GetAssertion(XmlElement el, out bool isEncrypted)
        {
            var encryptedList = el.GetElementsByTagName(EncryptedAssertion.ElementName, Saml20Constants.ASSERTION);
            if (encryptedList.Count == 1)
            {
                isEncrypted = true;
                return (XmlElement)encryptedList[0];
            }

            var assertionList = el.GetElementsByTagName(Assertion.ElementName, Saml20Constants.ASSERTION);
            if (assertionList.Count == 1)
            {
                isEncrypted = false;
                return (XmlElement)assertionList[0];
            }

            isEncrypted = false;

            return null;
        }


        #endregion

        #region Protected methods

        /// <summary>
        /// Is called before the assertion is made into a strongly typed representation
        /// </summary>
        /// <param name="context">The httpcontext.</param>
        /// <param name="elem">The assertion element.</param>
        /// <param name="endpoint">The endpoint.</param>
        protected virtual void PreHandleAssertion(HttpContext context, XmlElement elem, IdentityProviderElement endpoint)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "PreHandleAssertion");

            if (endpoint != null && endpoint.Endpoints.LogoutEndpoint != null && !String.IsNullOrEmpty(endpoint.Endpoints.LogoutEndpoint.TokenAccessor))
            {
                var idpTokenAccessor = Activator.CreateInstance(Type.GetType(endpoint.Endpoints.LogoutEndpoint.TokenAccessor, false)) as ISaml20IdpTokenAccessor;
                if (idpTokenAccessor != null)
                {
                    idpTokenAccessor.ReadToken(elem);
                }
            }

            Logger.DebugFormat("{0}.{1} finished", GetType(), "PreHandleAssertion");
        }

        #endregion

        #region Private methods - Helpers

        /// <summary>
        /// Determines whether the certificate is satisfied by all specifications.
        /// </summary>
        /// <param name="idp">The idp.</param>
        /// <param name="cert">The cert.</param>
        /// <returns><c>true</c> if [is satisfied by all specifications] [the specified ep]; otherwise, <c>false</c>.</returns>
        private static bool CertificateSatisfiesSpecifications(IdentityProviderElement idp, X509Certificate2 cert)
        {
            return SpecificationFactory.GetCertificateSpecifications(idp).All(spec => spec.IsSatisfiedBy(cert));
        }
        
        /// <summary>
        /// Checks for replay attack.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="inResponseTo">The message the current instance is in response to.</param>
        private static void CheckReplayAttack(HttpContext context, string inResponseTo)
        {
            var expectedInResponseToSessionState = context.Session[ExpectedInResponseToSessionKey];
            if (expectedInResponseToSessionState == null)
            {
                throw new Saml20Exception("Your session has been disconnected, please logon again");
            }

            var expectedInResponseTo = expectedInResponseToSessionState.ToString();
            if (string.IsNullOrEmpty(expectedInResponseTo) || string.IsNullOrEmpty(inResponseTo))
            {
                throw new Saml20Exception("Empty protocol message id is not allowed.");
            }

            if (inResponseTo != expectedInResponseTo)
            {
                Logger.ErrorFormat("Unexpected value {0} for InResponseTo, expected {1}, possible replay attack!", inResponseTo, expectedInResponseTo);
                throw new Saml20Exception("Replay attack.");
            }
        }

        /// <summary>
        /// Gets the decoded saml response.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="encoding">The encoding.</param>
        /// <returns>The decoded SAML response XML.</returns>
        private static XmlDocument GetDecodedSamlResponse(HttpContext context, Encoding encoding)
        {
            var base64 = context.Request.Params["SAMLResponse"];

            var doc = new XmlDocument { PreserveWhitespace = true };
            var samlResponse = encoding.GetString(Convert.FromBase64String(base64));
            doc.LoadXml(samlResponse);

            Logger.DebugFormat("Decoded SAMLResponse, msg: {0}", samlResponse);

            return doc;
        }

        /// <summary>
        /// Gets the decrypted assertion.
        /// </summary>
        /// <param name="elem">The elem.</param>
        /// <returns>The decrypted <see cref="Saml20EncryptedAssertion"/>.</returns>
        private static Saml20EncryptedAssertion GetDecryptedAssertion(XmlElement elem)
        {
            var decryptedAssertion = new Saml20EncryptedAssertion((RSA)Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate().PrivateKey);
            decryptedAssertion.LoadXml(elem);
            decryptedAssertion.Decrypt();

            Logger.Debug("Decrypted assertion: " + decryptedAssertion.Assertion.DocumentElement.OuterXml);

            return decryptedAssertion;
        }

        /// <summary>
        /// Retrieves the name of the issuer from an XmlElement containing an assertion.
        /// </summary>
        /// <param name="assertion">An XmlElement containing an assertion</param>
        /// <returns>The identifier of the Issuer</returns>
        private static string GetIssuer(XmlElement assertion)
        {
            var result = string.Empty;
            var list = assertion.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            if (list.Count > 0)
            {
                var issuer = (XmlElement)list[0];
                result = issuer.InnerText;
            }

            return result;
        }

        /// <summary>
        /// Gets the status element.
        /// </summary>
        /// <param name="doc">The doc.</param>
        /// <returns>The <see cref="Status"/> element.</returns>
        private static Status GetStatusElement(XmlDocument doc)
        {
            var statElem = (XmlElement)doc.GetElementsByTagName(Status.ElementName, Saml20Constants.PROTOCOL)[0];
            return Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
        }

        #endregion

        #region Private  methods - Handlers

        /// <summary>
        /// Handles executing the login.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="assertion">The assertion.</param>
        private void DoSignOn(HttpContext context, Saml20Assertion assertion)
        {
            //User is now logged in at IDP specified in tmp
            context.Session[IDPLoginSessionKey] = context.Session[IDPTempSessionKey];
            context.Session[IDPSessionIdKey] = assertion.SessionIndex;
            context.Session[IDPNameIdFormat] = assertion.Subject.Format;
            context.Session[IDPNameId] = assertion.Subject.Value;

            Logger.DebugFormat(Tracing.Login, assertion.Subject.Value, assertion.SessionIndex, assertion.Subject.Format);

            foreach (var action in Actions.Actions.GetActions())
            {
                Logger.Debug("Processing Signon request and executing Actions.");
                Logger.DebugFormat("{0}.{1} called", action.GetType(), "LoginAction()");

                action.SignOnAction(this, context, assertion);

                Logger.DebugFormat("{0}.{1} finished", action.GetType(), "LoginAction()");
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
        /// Deserializes an assertion, verifies its signature and logs in the user if the assertion is valid.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="elem">The elem.</param>
        private void HandleAssertion(HttpContext context, XmlElement elem)
        {
            Logger.Debug("Processing Assertion.");

            var issuer = GetIssuer(elem);
            var endp = RetrieveIDPConfiguration(issuer);

            PreHandleAssertion(context, elem, endp);

            if (endp == null || endp.Metadata == null)
            {
                Logger.Error("Unknown login IDP, assertion: " + elem);
                HandleError(context, Resources.UnknownLoginIDP);
                return;
            }

            var quirksMode = endp.QuirksMode;
            var assertion = new Saml20Assertion(elem, null, quirksMode);

            // Check signatures
            if (!endp.OmitAssertionSignatureCheck)
            {
                if (!assertion.CheckSignature(GetTrustedSigners(endp.Metadata.GetKeys(KeyTypes.Signing), endp)))
                {
                    Logger.Error("Invalid signature, assertion: " + elem);
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }
            }

            // Check expiration
            if (assertion.IsExpired)
            {
                Logger.Error("Assertion expired, assertion: " + elem.OuterXml);
                HandleError(context, Resources.AssertionExpired);
                return;
            }

            // Check one time use
            if (assertion.IsOneTimeUse)
            {
                if (context.Cache[assertion.Id] != null)
                {
                    Logger.Error(Resources.OneTimeUseReplay);
                    HandleError(context, Resources.OneTimeUseReplay);
                }
                else
                {
                    context.Cache.Insert(assertion.Id, string.Empty, null, assertion.NotOnOrAfter, Cache.NoSlidingExpiration);
                }
            }

            Logger.DebugFormat("Assertion with id {0} validated succesfully", assertion.Id);

            DoSignOn(context, assertion);
        }

        /// <summary>
        /// Decrypts an encrypted assertion, and sends the result to the HandleAssertion method.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="elem">The elem.</param>
        private void HandleEncryptedAssertion(HttpContext context, XmlElement elem)
        {
            var decryptedAssertion = GetDecryptedAssertion(elem);

            Logger.Debug("Encrypted Assertion was decrypted: " + decryptedAssertion.Assertion.DocumentElement);

            HandleAssertion(context, decryptedAssertion.Assertion.DocumentElement);
        }
        
        /// <summary>
        /// Handle the authentication response from the IDP.
        /// </summary>
        private void HandleResponse(HttpContext context)
        {
            var defaultEncoding = Encoding.UTF8;
            var doc = GetDecodedSamlResponse(context, defaultEncoding);

            Logger.Debug("Received SAMLResponse: " + doc.OuterXml);

            try
            {
                var inResponseToAttribute = doc.DocumentElement.Attributes["InResponseTo"];
                if (inResponseToAttribute == null)
                {
                    throw new Saml20Exception("Received a response message that did not contain an InResponseTo attribute");
                }

                var inResponseTo = inResponseToAttribute.Value;

                CheckReplayAttack(context, inResponseTo);

                var status = GetStatusElement(doc);
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    if (status.StatusCode.Value == Saml20Constants.StatusCodes.NoPassive)
                    {
                        Logger.Error("IdP responded with statuscode NoPassive. A user cannot be signed in with the IsPassiveFlag set when the user does not have a session with the IdP.");
                        HandleError(context, "IdP responded with statuscode NoPassive. A user cannot be signed in with the IsPassiveFlag set when the user does not have a session with the IdP.");
                    }

                    Logger.Error("Returned status was not successful: " + status);
                    HandleError(context, status);
                    return;
                }

                // Determine whether the assertion should be decrypted before being validated.
                bool isEncrypted;
                var assertion = GetAssertion(doc.DocumentElement, out isEncrypted);
                if (isEncrypted)
                {
                    assertion = GetDecryptedAssertion(assertion).Assertion.DocumentElement;
                }

                // Check if an encoding-override exists for the IdP endpoint in question
                var issuer = GetIssuer(assertion);
                var endpoint = RetrieveIDPConfiguration(issuer);
                if (!string.IsNullOrEmpty(endpoint.ResponseEncoding))
                {
                    Encoding encodingOverride;
                    try
                    {
                        encodingOverride = Encoding.GetEncoding(endpoint.ResponseEncoding);
                    }
                    catch (ArgumentException ex)
                    {
                        Logger.Error(Resources.UnknownEncodingFormat(endpoint.ResponseEncoding));
                        HandleError(context, ex);
                        return;
                    }

                    if (encodingOverride.CodePage != defaultEncoding.CodePage)
                    {
                        var doc1 = GetDecodedSamlResponse(context, encodingOverride);
                        assertion = GetAssertion(doc1.DocumentElement, out isEncrypted);
                    }
                }

                HandleAssertion(context, assertion);
            }
            catch (Exception e)
            {
                Logger.Error(Resources.GenericError, e);
                HandleError(context, e);
            }
        }

        /// <summary>
        /// Handles the SOAP.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="inputStream">The input stream.</param>
        private void HandleSoap(HttpContext context, Stream inputStream)
        {
            Logger.DebugFormat("SP initiated SOAP based Signon.");

            var parser = new HttpArtifactBindingParser(inputStream);
            var builder = new HttpArtifactBindingBuilder(context);

            if (parser.IsArtifactResolve)
            {
                Logger.Debug(Tracing.ArtifactResolveIn);

                var idp = RetrieveIDPConfiguration(parser.Issuer);
                if (!parser.CheckSamlMessageSignature(idp.Metadata.Keys))
                {
                    Logger.Error("Could not verify signature, msg: " + parser.SamlMessage);
                    HandleError(context, "Invalid Saml message signature");
                }

                builder.RespondToArtifactResolve(parser.ArtifactResolve);
            }
            else if (parser.IsArtifactResponse)
            {
                Logger.Debug(Tracing.ArtifactResponseIn);

                var status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    HandleError(context, status);
                    Logger.ErrorFormat("Illegal status for ArtifactResponse {0} expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage);
                    return;
                }

                if (parser.ArtifactResponse.Any.LocalName == Response.ElementName)
                {
                    bool isEncrypted;
                    var assertion = GetAssertion(parser.ArtifactResponse.Any, out isEncrypted);
                    if (assertion == null)
                    {
                        Logger.Error("Missing assertion.");
                        HandleError(context, "Missing assertion");
                    }

                    if (isEncrypted)
                    {
                        HandleEncryptedAssertion(context, assertion);
                    }
                    else
                    {
                        HandleAssertion(context, assertion);
                    }
                }
                else
                {
                    Logger.ErrorFormat("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage);
                    HandleError(context, string.Format("Unsupported payload message in ArtifactResponse: {0}", parser.ArtifactResponse.Any.LocalName));
                }
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
        /// Send an authentication request to the IDP.
        /// </summary>
        private void SendRequest(HttpContext context)
        {
            Logger.Debug("Sending SAML Request.");

            // See if the "ReturnUrl" - parameter is set.
            var returnUrl = context.Request.QueryString["ReturnUrl"];
            if (!string.IsNullOrEmpty(returnUrl))
            {
                context.Session["RedirectUrl"] = returnUrl;
            }            

            var idp = RetrieveIDP(context);
            if (idp == null)
            {
                //Display a page to the user where she can pick the IDP
                var page = new SelectSaml20IDP();
                page.ProcessRequest(context);
                return;
            }

            var authnRequest = Saml20AuthnRequest.GetDefault();
            TransferClient(idp, authnRequest, context);            
        }

        /// <summary>
        /// Transfers the client.
        /// </summary>
        /// <param name="identityProvider">The identity provider.</param>
        /// <param name="request">The request.</param>
        /// <param name="context">The context.</param>
        private void TransferClient(IdentityProviderElement identityProvider, Saml20AuthnRequest request, HttpContext context)
        {
            //Set the last IDP we attempted to login at.
            context.Session[IDPTempSessionKey]= identityProvider.Id;

            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            var destination = DetermineEndpointConfiguration(BindingType.Redirect, identityProvider.Endpoints.SignOnEndpoint, identityProvider.Metadata.SSOEndpoints);
            request.Destination = destination.Url;

            if (identityProvider.ForceAuth)
            {
                request.ForceAuthn = true;
            }

            // Check isPassive status
            var isPassiveFlag = context.Session[IDPIsPassive];
            if (isPassiveFlag != null && (bool)isPassiveFlag)
            {
                request.IsPassive = true;
                context.Session[IDPIsPassive] = null;
            }

            if (identityProvider.IsPassive)
            {
                request.IsPassive = true;
            }

            // Check if request should forceAuthn
            var forceAuthnFlag = context.Session[IDPForceAuthn];
            if (forceAuthnFlag != null && (bool)forceAuthnFlag)
            {
                request.ForceAuthn = true;
                context.Session[IDPForceAuthn] = null;
            }

            // Check if protocol binding should be forced
            if (identityProvider.Endpoints.SignOnEndpoint != null)
            {
                if (!string.IsNullOrEmpty(identityProvider.Endpoints.SignOnEndpoint.ForceProtocolBinding))
                {
                    request.ProtocolBinding = identityProvider.Endpoints.SignOnEndpoint.ForceProtocolBinding;
                }
            }

            //Save request message id to session
            context.Session.Add(ExpectedInResponseToSessionKey, request.Id);

            // Handle Redirect binding
            if (destination.Binding == BindingType.Redirect)
            {
                Logger.DebugFormat(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Redirect, identityProvider.Id);

                var builder = new HttpRedirectBindingBuilder
                                  {
                                      SigningKey = _certificate.PrivateKey,
                                      Request = request.GetXml().OuterXml
                                  };
                var s = request.Destination + "?" + builder.ToQuery();

                context.Response.Redirect(s, true);
                return;
            }

            // Handle Post binding
            if (destination.Binding == BindingType.Post)
            {
                Logger.DebugFormat(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Post, identityProvider.Id);

                var builder = new HttpPostBindingBuilder(destination);
                //Honor the ForceProtocolBinding and only set this if it's not already set
                if (string.IsNullOrEmpty(request.ProtocolBinding))
                {
                    request.ProtocolBinding = Saml20Constants.ProtocolBindings.HTTP_Post;
                }
                var req = request.GetXml();
                XmlSignatureUtils.SignDocument(req, request.Id);
                builder.Request = req.OuterXml;

                builder.GetPage().ProcessRequest(context);
                return;
            }

            // Handle Artifact binding
            if (destination.Binding == BindingType.Artifact)
            {
                Logger.DebugFormat(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Artifact, identityProvider.Id);

                var builder = new HttpArtifactBindingBuilder(context);
                //Honor the ForceProtocolBinding and only set this if it's not already set
                if (string.IsNullOrEmpty(request.ProtocolBinding))
                {
                    request.ProtocolBinding = Saml20Constants.ProtocolBindings.HTTP_Artifact;
                }

                builder.RedirectFromLogin(destination, request);
            }

            Logger.Error(Resources.BindingError);
            HandleError(context, Resources.BindingError);
        }

        #endregion

        #region IHttpHandler Members

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Logger.Debug("Signon handler called.");

            //Some IdP's are known to fail to set an actual value in the SOAPAction header
            //so we just check for the existence of the header field.
            if (Array.Exists(context.Request.Headers.AllKeys, s => s == SoapConstants.SoapAction))
            {
                HandleSoap(context, context.Request.InputStream);
                return;
            }

            if (!string.IsNullOrEmpty(context.Request.Params["SAMLart"]))
            {
                HandleArtifact(context);
            }

            if (!string.IsNullOrEmpty(context.Request.Params["SamlResponse"]))
            {
                HandleResponse(context);
            }
            else
            {
                if (Saml2Config.GetConfig().CommonDomainCookie.Enabled && context.Request.QueryString["r"] == null
                    && context.Request.Params["cidp"] == null)
                {
                    Logger.Debug("Redirecting to Common Domain for IDP discovery.");
                    context.Response.Redirect(Saml2Config.GetConfig().CommonDomainCookie.LocalReaderEndpoint);
                }
                else
                {
                    Logger.Warn("User accessing resource: " + context.Request.RawUrl + " without authentication.");
                    SendRequest(context);
                }
            }
        }

        #endregion
    }
}
