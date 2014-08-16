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
using SAML2.Protocol.Pages;
using SAML2.Schema.Core;
using SAML2.Schema.Metadata;
using SAML2.Schema.Protocol;
using SAML2.Specification;
using SAML2.Utils;

namespace SAML2.Protocol
{
    /// <summary>
    /// Implements a SAML 2.0 protocol sign-on endpoint. Handles all SAML bindings.
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
        private readonly X509Certificate2 _certificate;

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
            catch (Exception e)
            {
                Logger.Error(e.Message, e);
            }
        }

        #region Public methods

        /// <summary>
        /// Gets the trusted signers.
        /// </summary>
        /// <param name="keys">The keys.</param>
        /// <param name="identityProvider">The identity provider.</param>
        /// <returns>List of trusted certificate signers.</returns>
        public static IEnumerable<AsymmetricAlgorithm> GetTrustedSigners(ICollection<KeyDescriptor> keys, IdentityProviderElement identityProvider)
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
                        if (!CertificateSatisfiesSpecifications(identityProvider, cert))
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
            Logger.Debug(TraceMessages.AssertionParse);

            var encryptedList = el.GetElementsByTagName(EncryptedAssertion.ElementName, Saml20Constants.Assertion);
            if (encryptedList.Count == 1)
            {
                isEncrypted = true;
                var encryptedAssertion = (XmlElement)encryptedList[0];

                Logger.DebugFormat(TraceMessages.EncryptedAssertionFound, encryptedAssertion.OuterXml);

                return encryptedAssertion;
            }

            var assertionList = el.GetElementsByTagName(Assertion.ElementName, Saml20Constants.Assertion);
            if (assertionList.Count == 1)
            {
                isEncrypted = false;
                var assertion = (XmlElement)assertionList[0];

                Logger.DebugFormat(TraceMessages.AssertionFound, assertion.OuterXml);

                return assertion;
            }

            Logger.Warn(ErrorMessages.AssertionNotFound);

            isEncrypted = false;
            return null;
        }

        #endregion

        #region Protected methods

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Logger.Debug(TraceMessages.SignOnHandlerCalled);

            // Some IdP's are known to fail to set an actual value in the SOAPAction header
            // so we just check for the existence of the header field.
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
                    Logger.Debug(TraceMessages.CommonDomainCookieRedirectForDiscovery);
                    context.Response.Redirect(Saml2Config.GetConfig().CommonDomainCookie.LocalReaderEndpoint);
                }
                else
                {
                    Logger.WarnFormat(ErrorMessages.UnauthenticatedAccess, context.Request.RawUrl);
                    SendRequest(context);
                }
            }
        }

        /// <summary>
        /// Is called before the assertion is made into a strongly typed representation
        /// </summary>
        /// <param name="context">The HttpContext.</param>
        /// <param name="elem">The assertion element.</param>
        /// <param name="endpoint">The endpoint.</param>
        protected virtual void PreHandleAssertion(HttpContext context, XmlElement elem, IdentityProviderElement endpoint)
        {
            Logger.DebugFormat(TraceMessages.AssertionPrehandlerCalled);

            if (endpoint != null && endpoint.Endpoints.LogoutEndpoint != null && !string.IsNullOrEmpty(endpoint.Endpoints.LogoutEndpoint.TokenAccessor))
            {
                var idpTokenAccessor = Activator.CreateInstance(Type.GetType(endpoint.Endpoints.LogoutEndpoint.TokenAccessor, false)) as ISaml20IdpTokenAccessor;
                if (idpTokenAccessor != null)
                {
                    Logger.DebugFormat("{0}.{1} called", idpTokenAccessor.GetType(), "ReadToken");
                    idpTokenAccessor.ReadToken(elem);
                    Logger.DebugFormat("{0}.{1} finished", idpTokenAccessor.GetType(), "ReadToken");
                }
            }
        }

        #endregion

        #region Private methods - Helpers

        /// <summary>
        /// Determines whether the certificate is satisfied by all specifications.
        /// </summary>
        /// <param name="idp">The identity provider.</param>
        /// <param name="cert">The cert.</param>
        /// <returns><c>true</c> if certificate is satisfied by all specifications; otherwise, <c>false</c>.</returns>
        private static bool CertificateSatisfiesSpecifications(IdentityProviderElement idp, X509Certificate2 cert)
        {
            return SpecificationFactory.GetCertificateSpecifications(idp).All(spec => spec.IsSatisfiedBy(cert));
        }

        /// <summary>
        /// Checks for replay attack.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="element">The element.</param>
        private static void CheckReplayAttack(HttpContext context, XmlElement element)
        {
            Logger.Debug(TraceMessages.ReplayAttackCheck);

            var inResponseToAttribute = element.Attributes["InResponseTo"];
            if (inResponseToAttribute == null)
            {
                throw new Saml20Exception(ErrorMessages.ResponseMissingInResponseToAttribute);
            }

            var inResponseTo = inResponseToAttribute.Value;
            if (string.IsNullOrEmpty(inResponseTo))
            {
                throw new Saml20Exception(ErrorMessages.ExpectedInResponseToEmpty);
            }

            var expectedInResponseTo = StateService.Get<string>(ExpectedInResponseToSessionKey);
            if (string.IsNullOrEmpty(expectedInResponseTo))
            {
                throw new Saml20Exception(ErrorMessages.ExpectedInResponseToMissing);
            }

            if (inResponseTo != expectedInResponseTo)
            {
                Logger.ErrorFormat(ErrorMessages.ReplayAttack, inResponseTo, expectedInResponseTo);
                throw new Saml20Exception(string.Format(ErrorMessages.ReplayAttack, inResponseTo, expectedInResponseTo));
            }

            Logger.Debug(TraceMessages.ReplaceAttackCheckCleared);
        }

        /// <summary>
        /// Gets the decoded SAML response.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="encoding">The encoding.</param>
        /// <returns>The decoded SAML response XML.</returns>
        private static XmlDocument GetDecodedSamlResponse(HttpContext context, Encoding encoding)
        {
            Logger.Debug(TraceMessages.SamlResponseDecoding);

            var base64 = context.Request.Params["SAMLResponse"];

            var doc = new XmlDocument { PreserveWhitespace = true };
            var samlResponse = encoding.GetString(Convert.FromBase64String(base64));
            doc.LoadXml(samlResponse);

            Logger.DebugFormat(TraceMessages.SamlResponseDecoded, samlResponse);

            return doc;
        }

        /// <summary>
        /// Gets the decrypted assertion.
        /// </summary>
        /// <param name="elem">The elem.</param>
        /// <returns>The decrypted <see cref="Saml20EncryptedAssertion"/>.</returns>
        private static Saml20EncryptedAssertion GetDecryptedAssertion(XmlElement elem)
        {
            Logger.Debug(TraceMessages.EncryptedAssertionDecrypting);

            var decryptedAssertion = new Saml20EncryptedAssertion((RSA)Saml2Config.GetConfig().ServiceProvider.SigningCertificate.GetCertificate().PrivateKey);
            decryptedAssertion.LoadXml(elem);
            decryptedAssertion.Decrypt();

            Logger.DebugFormat(TraceMessages.EncryptedAssertionDecrypted, decryptedAssertion.Assertion.DocumentElement.OuterXml);

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
            var list = assertion.GetElementsByTagName("Issuer", Saml20Constants.Assertion);
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
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Status" /> element.</returns>
        private static Status GetStatusElement(XmlElement element)
        {
            var statElem = element.GetElementsByTagName(Status.ElementName, Saml20Constants.Protocol)[0];
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
            // User is now logged in at IDP specified in tmp
            StateService.Set(IdpLoginSessionKey, StateService.Get<string>(IdpTempSessionKey));
            StateService.Set(IdpSessionIdKey, assertion.SessionIndex);
            StateService.Set(IdpNameIdFormat, assertion.Subject.Format);
            StateService.Set(IdpNameId, assertion.Subject.Value);

            Logger.DebugFormat(TraceMessages.SignOnProcessed, assertion.SessionIndex, assertion.Subject.Value, assertion.Subject.Format);

            Logger.Debug(TraceMessages.SignOnActionsExecuting);
            foreach (var action in Actions.Actions.GetActions())
            {
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
            Logger.DebugFormat(TraceMessages.AssertionProcessing, elem.OuterXml);

            var issuer = GetIssuer(elem);
            var endp = RetrieveIDPConfiguration(issuer);

            PreHandleAssertion(context, elem, endp);

            if (endp == null || endp.Metadata == null)
            {
                Logger.Error(ErrorMessages.AssertionIdentityProviderUnknown);
                throw new Saml20Exception(ErrorMessages.AssertionIdentityProviderUnknown);
            }

            var quirksMode = endp.QuirksMode;
            var assertion = new Saml20Assertion(elem, null, Saml2Config.GetConfig().AssertionProfile.AssertionValidator, quirksMode);

            // Check signatures
            if (!endp.OmitAssertionSignatureCheck)
            {
                if (!assertion.CheckSignature(GetTrustedSigners(endp.Metadata.GetKeys(KeyTypes.Signing), endp)))
                {
                    Logger.Error(ErrorMessages.AssertionSignatureInvalid);
                    throw new Saml20Exception(ErrorMessages.AssertionSignatureInvalid);
                }
            }

            // Check expiration
            if (assertion.IsExpired)
            {
                Logger.Error(ErrorMessages.AssertionExpired);
                throw new Saml20Exception(ErrorMessages.AssertionExpired);
            }

            // Check one time use
            if (assertion.IsOneTimeUse)
            {
                if (context.Cache[assertion.Id] != null)
                {
                    Logger.Error(ErrorMessages.AssertionOneTimeUseExceeded);
                    throw new Saml20Exception(ErrorMessages.AssertionOneTimeUseExceeded);
                }

                context.Cache.Insert(assertion.Id, string.Empty, null, assertion.NotOnOrAfter, Cache.NoSlidingExpiration);
            }

            Logger.DebugFormat(TraceMessages.AssertionParsed, assertion.Id);

            DoSignOn(context, assertion);
        }

        /// <summary>
        /// Decrypts an encrypted assertion, and sends the result to the HandleAssertion method.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="elem">The elem.</param>
        private void HandleEncryptedAssertion(HttpContext context, XmlElement elem)
        {
            HandleAssertion(context, GetDecryptedAssertion(elem).Assertion.DocumentElement);
        }

        /// <summary>
        /// Handle the authentication response from the IDP.
        /// </summary>
        /// <param name="context">The context.</param>
        private void HandleResponse(HttpContext context)
        {
            var defaultEncoding = Encoding.UTF8;
            var doc = GetDecodedSamlResponse(context, defaultEncoding);
            Logger.DebugFormat(TraceMessages.SamlResponseReceived, doc.OuterXml);

            CheckReplayAttack(context, doc.DocumentElement);

            var status = GetStatusElement(doc.DocumentElement);
            if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
            {
                if (status.StatusCode.Value == Saml20Constants.StatusCodes.NoPassive)
                {
                    Logger.Error(ErrorMessages.ResponseStatusIsNoPassive);
                    throw new Saml20Exception(ErrorMessages.ResponseStatusIsNoPassive);
                }

                Logger.ErrorFormat(ErrorMessages.ResponseStatusNotSuccessful, status);
                throw new Saml20Exception(string.Format(ErrorMessages.ResponseStatusNotSuccessful, status));
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
                    Logger.ErrorFormat(ErrorMessages.UnknownEncoding, endpoint.ResponseEncoding);
                    throw new ArgumentException(string.Format(ErrorMessages.UnknownEncoding, endpoint.ResponseEncoding), ex);
                }

                if (encodingOverride.CodePage != defaultEncoding.CodePage)
                {
                    var doc1 = GetDecodedSamlResponse(context, encodingOverride);
                    assertion = GetAssertion(doc1.DocumentElement, out isEncrypted);
                }
            }

            HandleAssertion(context, assertion);
        }

        /// <summary>
        /// Handles the SOAP.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="inputStream">The input stream.</param>
        private void HandleSoap(HttpContext context, Stream inputStream)
        {
            var parser = new HttpArtifactBindingParser(inputStream);
            Logger.DebugFormat(TraceMessages.SOAPMessageParse, parser.SamlMessage.OuterXml);

            var builder = new HttpArtifactBindingBuilder(context);

            if (parser.IsArtifactResolve)
            {
                Logger.Debug(TraceMessages.ArtifactResolveReceived);

                var idp = RetrieveIDPConfiguration(parser.Issuer);
                if (!parser.CheckSamlMessageSignature(idp.Metadata.Keys))
                {
                    Logger.Error(ErrorMessages.ArtifactResolveSignatureInvalid);
                    throw new Saml20Exception(ErrorMessages.ArtifactResolveSignatureInvalid);
                }

                builder.RespondToArtifactResolve(parser.ArtifactResolve);
            }
            else if (parser.IsArtifactResponse)
            {
                Logger.Debug(TraceMessages.ArtifactResolveReceived);

                var idp = RetrieveIDPConfiguration(parser.Issuer);
                if (!parser.CheckSamlMessageSignature(idp.Metadata.Keys))
                {
                    Logger.Error(ErrorMessages.ArtifactResponseSignatureInvalid);
                    throw new Saml20Exception(ErrorMessages.ArtifactResponseSignatureInvalid);
                }

                var status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    Logger.ErrorFormat(ErrorMessages.ArtifactResponseStatusCodeInvalid, status.StatusCode.Value);
                    throw new Saml20Exception(string.Format(ErrorMessages.ArtifactResponseStatusCodeInvalid, status.StatusCode.Value));
                }

                if (parser.ArtifactResponse.Any.LocalName == Response.ElementName)
                {
                    CheckReplayAttack(context, parser.ArtifactResponse.Any);

                    var responseStatus = GetStatusElement(parser.ArtifactResponse.Any);
                    if (responseStatus.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                    {
                        Logger.ErrorFormat(ErrorMessages.ArtifactResponseStatusCodeInvalid, responseStatus.StatusCode.Value);
                        throw new Saml20Exception(string.Format(ErrorMessages.ArtifactResponseStatusCodeInvalid, responseStatus.StatusCode.Value));
                    }

                    bool isEncrypted;
                    var assertion = GetAssertion(parser.ArtifactResponse.Any, out isEncrypted);
                    if (assertion == null)
                    {
                        Logger.Error(ErrorMessages.ArtifactResponseMissingAssertion);
                        throw new Saml20Exception(ErrorMessages.ArtifactResponseMissingAssertion);
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
                    Logger.ErrorFormat(ErrorMessages.ArtifactResponseMissingResponse);
                    throw new Saml20Exception(ErrorMessages.ArtifactResponseMissingResponse);
                }
            }
            else
            {
                Logger.ErrorFormat(ErrorMessages.SOAPMessageUnsupportedSamlMessage);
                throw new Saml20Exception(ErrorMessages.SOAPMessageUnsupportedSamlMessage);
            }
        }

        /// <summary>
        /// Send an authentication request to the IDP.
        /// </summary>
        /// <param name="context">The context.</param>
        private void SendRequest(HttpContext context)
        {
            // See if the "ReturnUrl" - parameter is set.
            var returnUrl = context.Request.QueryString["ReturnUrl"];
            if (!string.IsNullOrEmpty(returnUrl))
            {
                StateService.Set("RedirectUrl", returnUrl);
            }

            var idp = RetrieveIDP(context);
            if (idp == null)
            {
                // Display a page to the user where she can pick the IDP
                Logger.DebugFormat(TraceMessages.IdentityProviderRedirect);

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
            // Set the last IDP we attempted to login at.
            StateService.Set(IdpTempSessionKey, identityProvider.Id);

            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            var destination = DetermineEndpointConfiguration(BindingType.Redirect, identityProvider.Endpoints.SignOnEndpoint, identityProvider.Metadata.SSOEndpoints);
            request.Destination = destination.Url;

            if (identityProvider.ForceAuth)
            {
                request.ForceAuthn = true;
            }

            // Check isPassive status
            var isPassiveFlag = StateService.Get<bool?>(IdpIsPassive);

            if (isPassiveFlag != null && (bool)isPassiveFlag)
            {
                request.IsPassive = true;
                StateService.Set(IdpIsPassive, null);
            }

            if (identityProvider.IsPassive)
            {
                request.IsPassive = true;
            }

            // Check if request should forceAuthn
            var forceAuthnFlag = StateService.Get<bool?>(IdpForceAuthn);
            if (forceAuthnFlag != null && (bool)forceAuthnFlag)
            {
                request.ForceAuthn = true;
                StateService.Set(IdpForceAuthn, null);
            }

            // Check if protocol binding should be forced
            if (identityProvider.Endpoints.SignOnEndpoint != null)
            {
                if (!string.IsNullOrEmpty(identityProvider.Endpoints.SignOnEndpoint.ForceProtocolBinding))
                {
                    request.ProtocolBinding = identityProvider.Endpoints.SignOnEndpoint.ForceProtocolBinding;
                }
            }

            // Save request message id to session
            StateService.Set(ExpectedInResponseToSessionKey, request.Id);

            switch (destination.Binding)
            {
                case BindingType.Redirect:
                    Logger.DebugFormat(TraceMessages.AuthnRequestPrepared, identityProvider.Id, Saml20Constants.ProtocolBindings.HttpRedirect);

                    var redirectBuilder = new HttpRedirectBindingBuilder
                                      {
                                          SigningKey = _certificate.PrivateKey,
                                          Request = request.GetXml().OuterXml
                                      };

                    Logger.DebugFormat(TraceMessages.AuthnRequestSent, redirectBuilder.Request);

                    var redirectLocation = request.Destination + "?" + redirectBuilder.ToQuery();
                    context.Response.Redirect(redirectLocation, true);
                    break;
                case BindingType.Post:
                    Logger.DebugFormat(TraceMessages.AuthnRequestPrepared, identityProvider.Id, Saml20Constants.ProtocolBindings.HttpPost);

                    var postBuilder = new HttpPostBindingBuilder(destination);

                    // Honor the ForceProtocolBinding and only set this if it's not already set
                    if (string.IsNullOrEmpty(request.ProtocolBinding))
                    {
                        request.ProtocolBinding = Saml20Constants.ProtocolBindings.HttpPost;
                    }

                    var requestXml = request.GetXml();
                    XmlSignatureUtils.SignDocument(requestXml, request.Id);
                    postBuilder.Request = requestXml.OuterXml;

                    Logger.DebugFormat(TraceMessages.AuthnRequestSent, postBuilder.Request);

                    postBuilder.GetPage().ProcessRequest(context);
                    break;
                case BindingType.Artifact:
                    Logger.DebugFormat(TraceMessages.AuthnRequestPrepared, identityProvider.Id, Saml20Constants.ProtocolBindings.HttpArtifact);

                    var artifactBuilder = new HttpArtifactBindingBuilder(context);

                    // Honor the ForceProtocolBinding and only set this if it's not already set
                    if (string.IsNullOrEmpty(request.ProtocolBinding))
                    {
                        request.ProtocolBinding = Saml20Constants.ProtocolBindings.HttpArtifact;
                    }

                    Logger.DebugFormat(TraceMessages.AuthnRequestSent, request.GetXml().OuterXml);

                    artifactBuilder.RedirectFromLogin(destination, request);
                    break;
                default:
                    Logger.Error(ErrorMessages.EndpointBindingInvalid);
                    throw new Saml20Exception(ErrorMessages.EndpointBindingInvalid);
            }
        }

        #endregion
    }
}
