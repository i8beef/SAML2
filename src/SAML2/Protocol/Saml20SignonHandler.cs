using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Caching;
using System.Xml;
using SAML2.Actions;
using SAML2.Bindings;
using SAML2.Config;
using SAML2.Identity;
using SAML2.Logging;
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
        private readonly X509Certificate2  _certificate;

        /// <summary>
        /// Session key used to save the current message id with the purpose of preventing replay attacks
        /// </summary>
        public const string ExpectedInResponseToSessionKey = "ExpectedInResponseTo";

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20SignonHandler"/> class.
        /// </summary>
        public Saml20SignonHandler()
        {
            _certificate = FederationConfig.GetConfig().SigningCertificate.GetCertificate();

            // Read the proper redirect url from config
            try
            {
                RedirectUrl = SAML20FederationConfig.GetConfig().ServiceProvider.SignOnEndpoint.RedirectUrl;
                ErrorBehaviour = SAML20FederationConfig.GetConfig().ServiceProvider.SignOnEndpoint.ErrorBehaviour.ToString();
            }
            catch(Exception e)
            {
                Logger.Error(e.Message, e);
            }
        }

        #region IHttpHandler Members

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "Handle()");

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
            }

            if (!string.IsNullOrEmpty(context.Request.Params["SamlResponse"]))
            {
                HandleResponse(context);
            }
            else
            {
                if (SAML20FederationConfig.GetConfig().CommonDomain.Enabled && context.Request.QueryString["r"] == null
                    && context.Request.Params["cidp"] == null)
                {
                    Logger.Debug("Redirecting to Common Domain for IDP discovery");
                    context.Response.Redirect(SAML20FederationConfig.GetConfig().CommonDomain.LocalReaderEndpoint);
                }
                else
                {
                    Logger.Warn("User accessing resource: " + context.Request.RawUrl +
                                                 " without authentication.");
                    SendRequest(context);
                }
            }
        }
                
        #endregion

        private void HandleArtifact(HttpContext context)
        {
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            Stream inputStream = builder.ResolveArtifact();
            HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "HandleSOAP");
            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);

            if(parser.IsArtifactResolve())
            {
                Logger.Debug(Tracing.ArtifactResolveIn);

                IDPEndPoint idp = RetrieveIDPConfiguration(parser.Issuer);
                if (!parser.CheckSamlMessageSignature(idp.metadata.Keys))
                {
                    HandleError(context, "Invalid Saml message signature");
                    Logger.Error("Could not verify signature, msg: " + parser.SamlMessage);
                };
                builder.RespondToArtifactResolve(parser.ArtifactResolve);
            }else if(parser.IsArtifactResponse())
            {
                Logger.Debug(Tracing.ArtifactResponseIn);

                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    HandleError(context, status);
                    Logger.ErrorFormat("Illegal status for ArtifactResponse {0} expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage);
                    return;
                }
                if(parser.ArtifactResponse.Any.LocalName == Response.ELEMENT_NAME)
                {
                    bool isEncrypted;
                    XmlElement assertion = GetAssertion(parser.ArtifactResponse.Any, out isEncrypted);
                    if (assertion == null)
                        HandleError(context, "Missing assertion");
                    if(isEncrypted)
                    {
                        HandleEncryptedAssertion(context, assertion);
                    }else
                    {
                        HandleAssertion(context, assertion);
                    }

                }else
                {
                    Logger.ErrorFormat("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage);
                    HandleError(context,
                                string.Format("Unsupported payload message in ArtifactResponse: {0}",
                                              parser.ArtifactResponse.Any.LocalName));
                }
            }else
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

        /// <summary>
        /// Send an authentication request to the IDP.
        /// </summary>
        private void SendRequest(HttpContext context)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "SendRequest()");

            // See if the "ReturnUrl" - parameter is set.
            string returnUrl = context.Request.QueryString["ReturnUrl"];
            if (!string.IsNullOrEmpty(returnUrl))            
                context.Session["RedirectUrl"] = returnUrl;            

            IDPEndPoint idpEndpoint = RetrieveIDP(context);

            if (idpEndpoint == null)
            {
                //Display a page to the user where she can pick the IDP
                SelectSaml20IDP page = new SelectSaml20IDP();
                page.ProcessRequest(context);
                return;
            }

            Saml20AuthnRequest authnRequest = Saml20AuthnRequest.GetDefault();
            TransferClient(idpEndpoint, authnRequest, context);            
        }


        private Status GetStatusElement(XmlDocument doc)
        {
            XmlElement statElem =
                (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            return Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
        }

        internal static XmlElement GetAssertion(XmlElement el, out bool isEncrypted)
        {
            
            XmlNodeList encryptedList =
                el.GetElementsByTagName(EncryptedAssertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (encryptedList.Count == 1)
            {
                isEncrypted = true;
                return (XmlElement)encryptedList[0];
            }

            XmlNodeList assertionList =
                el.GetElementsByTagName(Assertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (assertionList.Count == 1)
            {
                isEncrypted = false;
                return (XmlElement)assertionList[0];
            }

            isEncrypted = false;
            return null;
        }

        /// <summary>
        /// Handle the authentication response from the IDP.
        /// </summary>        
        private void HandleResponse(HttpContext context)
        {
            Encoding defaultEncoding = Encoding.UTF8;
            XmlDocument doc = GetDecodedSamlResponse(context, defaultEncoding);

            Logger.Debug("Received SAMLResponse: " + doc.OuterXml);

            try
            {

                XmlAttribute inResponseToAttribute =
                    doc.DocumentElement.Attributes["InResponseTo"];

                if(inResponseToAttribute == null)
                    throw new Saml20Exception("Received a response message that did not contain an InResponseTo attribute");

                string inResponseTo = inResponseToAttribute.Value;

                CheckReplayAttack(context, inResponseTo);
                
                Status status = GetStatusElement(doc);

                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    if (status.StatusCode.Value == Saml20Constants.StatusCodes.NoPassive)
                        HandleError(context, "IdP responded with statuscode NoPassive. A user cannot be signed in with the IsPassiveFlag set when the user does not have a session with the IdP.");

                    HandleError(context, status);
                    return;
                }

                // Determine whether the assertion should be decrypted before being validated.
            
                bool isEncrypted;
                XmlElement assertion = GetAssertion(doc.DocumentElement, out isEncrypted);
                if (isEncrypted)
                {
                    assertion = GetDecryptedAssertion(assertion).Assertion.DocumentElement;
                }

                // Check if an encoding-override exists for the IdP endpoint in question
                string issuer = GetIssuer(assertion);
                IDPEndPoint endpoint = RetrieveIDPConfiguration(issuer);
                if (!string.IsNullOrEmpty(endpoint.ResponseEncoding))
                {
                    Encoding encodingOverride = null;
                    try
                    {
                        encodingOverride = System.Text.Encoding.GetEncoding(endpoint.ResponseEncoding);
                    }
                    catch (ArgumentException ex)
                    {
                        HandleError(context, ex);
                        return;
                    }

                    if (encodingOverride.CodePage != defaultEncoding.CodePage)
                    {
                        XmlDocument doc1 = GetDecodedSamlResponse(context, encodingOverride);
                        assertion = GetAssertion(doc1.DocumentElement, out isEncrypted);
                    }
                }

                HandleAssertion(context, assertion);
                return;
            }
            catch (Exception e)
            {
                HandleError(context, e);
                return;
            }
        }

        private static void CheckReplayAttack(HttpContext context, string inResponseTo)
        {
            var expectedInResponseToSessionState = context.Session[ExpectedInResponseToSessionKey];
            if (expectedInResponseToSessionState == null)
                throw new Saml20Exception("Your session has been disconnected, please logon again");

            string expectedInResponseTo = expectedInResponseToSessionState.ToString();
            if (string.IsNullOrEmpty(expectedInResponseTo) || string.IsNullOrEmpty(inResponseTo))
                throw new Saml20Exception("Empty protocol message id is not allowed.");

            if (inResponseTo != expectedInResponseTo)
            {
                Logger.ErrorFormat("Unexpected value {0} for InResponseTo, expected {1}, possible replay attack!", inResponseTo, expectedInResponseTo);
                throw new Saml20Exception("Replay attack.");
            }

         }

        private static XmlDocument GetDecodedSamlResponse(HttpContext context, Encoding encoding)
        {
            string base64 = context.Request.Params["SAMLResponse"];

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string samlResponse = encoding.GetString(Convert.FromBase64String(base64));
            Logger.DebugFormat("Decoded SAMLResponse, msg: {0}", samlResponse);

            doc.LoadXml(samlResponse);
            return doc;
        }

        /// <summary>
        /// Decrypts an encrypted assertion, and sends the result to the HandleAssertion method.
        /// </summary>
        private void HandleEncryptedAssertion(HttpContext context, XmlElement elem)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "HandleEncryptedAssertion()");
            Saml20EncryptedAssertion decryptedAssertion = GetDecryptedAssertion(elem);
            HandleAssertion(context, decryptedAssertion.Assertion.DocumentElement);
        }

        private static Saml20EncryptedAssertion GetDecryptedAssertion(XmlElement elem)
        {
            Saml20EncryptedAssertion decryptedAssertion = new Saml20EncryptedAssertion((RSA)FederationConfig.GetConfig().SigningCertificate.GetCertificate().PrivateKey);
            decryptedAssertion.LoadXml(elem);
            decryptedAssertion.Decrypt();
            return decryptedAssertion;
        }

        /// <summary>
        /// Retrieves the name of the issuer from an XmlElement containing an assertion.
        /// </summary>
        /// <param name="assertion">An XmlElement containing an assertion</param>
        /// <returns>The identifier of the Issuer</returns>
        private string GetIssuer(XmlElement assertion)
        {
            string result = string.Empty;
            XmlNodeList list = assertion.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            if (list.Count > 0)
            {
                XmlElement issuer = (XmlElement) list[0];
                result = issuer.InnerText;
            }

            return result;
        }

        /// <summary>
        /// Is called before the assertion is made into a strongly typed representation
        /// </summary>
        /// <param name="context">The httpcontext.</param>
        /// <param name="elem">The assertion element.</param>
        /// <param name="endpoint">The endpoint.</param>
        protected virtual void PreHandleAssertion(HttpContext context, XmlElement elem, IDPEndPoint endpoint)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "PreHandleAssertion");

            if (endpoint != null && endpoint.SLOEndpoint != null && !String.IsNullOrEmpty(endpoint.SLOEndpoint.IdpTokenAccessor))
            {
                ISaml20IdpTokenAccessor idpTokenAccessor =
                    Activator.CreateInstance(Type.GetType(endpoint.SLOEndpoint.IdpTokenAccessor, false)) as ISaml20IdpTokenAccessor;
                if (idpTokenAccessor != null)
                    idpTokenAccessor.ReadToken(elem);
            }

            Logger.DebugFormat("{0}.{1} finished", GetType(), "PreHandleAssertion");
        }

        /// <summary>
        /// Deserializes an assertion, verifies its signature and logs in the user if the assertion is valid.
        /// </summary>
        private void HandleAssertion(HttpContext context, XmlElement elem)
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "HandleAssertion");

            string issuer = GetIssuer(elem);
            
            IDPEndPoint endp = RetrieveIDPConfiguration(issuer);

            PreHandleAssertion(context, elem, endp);

            bool quirksMode = false;

            if (endp != null)
            {
                quirksMode = endp.QuirksMode;
            }
            
            Saml20Assertion assertion = new Saml20Assertion(elem, null, quirksMode);
                        
            if (endp == null || endp.metadata == null)
            {
                Logger.Error("Unknown login IDP, assertion: " + elem);
                HandleError(context, Resources.UnknownLoginIDP);
                return;
            }

            if (!endp.OmitAssertionSignatureCheck)
            {
                if (!assertion.CheckSignature(GetTrustedSigners(endp.metadata.GetKeys(KeyTypes.signing), endp)))
                {
                    Logger.Error("Invalid signature, assertion: " + elem);
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }
            }

            if (assertion.IsExpired())
            {
                Logger.Error("Assertion expired, assertion: " + elem.OuterXml);
                HandleError(context, Resources.AssertionExpired);
                return;
            }

            CheckConditions(context, assertion);
            Logger.DebugFormat("Assertion with id {0} validated succesfully", assertion.Id);

            DoLogin(context, assertion);
        }

        internal static IEnumerable<AsymmetricAlgorithm> GetTrustedSigners(ICollection<KeyDescriptor> keys, IDPEndPoint ep)
        {
            if (keys == null)
                throw new ArgumentNullException("keys");

            List<AsymmetricAlgorithm> result = new List<AsymmetricAlgorithm>(keys.Count);
            foreach (KeyDescriptor keyDescriptor in keys)
            {
                KeyInfo ki = (KeyInfo) keyDescriptor.KeyInfo;
                    
                foreach (KeyInfoClause clause in ki)
                {
                    if(clause is KeyInfoX509Data)
                    {
                        X509Certificate2 cert = XmlSignatureUtils.GetCertificateFromKeyInfo((KeyInfoX509Data) clause);

                        if (!IsSatisfiedByAllSpecifications(ep, cert))
                            continue;
                    }

                    AsymmetricAlgorithm key = XmlSignatureUtils.ExtractKey(clause);
                    result.Add(key);
                }
                
            }

            return result;
        }

        private static bool IsSatisfiedByAllSpecifications(IDPEndPoint ep, X509Certificate2 cert)
        {
            foreach(ICertificateSpecification spec in SpecificationFactory.GetCertificateSpecifications(ep))
            {
                if (!spec.IsSatisfiedBy(cert))
                    return false;   
            }

            return true;
        }


        private void CheckConditions(HttpContext context, Saml20Assertion assertion)
        {
            if(assertion.IsOneTimeUse)
            {
                if (context.Cache[assertion.Id] != null)
                {
                    HandleError(context, Resources.OneTimeUseReplay);
                }else
                {
                    context.Cache.Insert(assertion.Id, string.Empty, null, assertion.NotOnOrAfter, Cache.NoSlidingExpiration);
                }
            }
        }

        private void DoLogin(HttpContext context, Saml20Assertion assertion)
        {
            //User is now logged in at IDP specified in tmp
            context.Session[IDPLoginSessionKey] = context.Session[IDPTempSessionKey];
            context.Session[IDPSessionIdKey] = assertion.SessionIndex;
            context.Session[IDPNameIdFormat] = assertion.Subject.Format;
            context.Session[IDPNameId] = assertion.Subject.Value;

            Logger.DebugFormat(Tracing.Login, assertion.Subject.Value, assertion.SessionIndex, assertion.Subject.Format);

            string inResponseTo = "(unknown)";
            if (assertion.GetSubjectConfirmationData() != null && assertion.GetSubjectConfirmationData().InResponseTo != null)
                inResponseTo = assertion.GetSubjectConfirmationData().InResponseTo;

            string assuranceLevel = "(unknown)";
            foreach(var attribute in assertion.Attributes)
            {
                if (attribute.Name == "dk:gov:saml:attribute:AssuranceLevel"
                    && attribute.AttributeValue != null 
                    && attribute.AttributeValue.Length > 0)
                    assuranceLevel =  attribute.AttributeValue[0];
            }
            
            Logger.DebugFormat("Subject: {0} NameIDFormat: {1}  Level of authentication: {2}  Session timeout in minutes: {3}", assertion.Subject.Value, assertion.Subject.Format, assuranceLevel, HttpContext.Current.Session.Timeout);

            foreach(IAction action in Actions.Actions.GetActions())
            {
                Logger.DebugFormat("{0}.{1} called", action.GetType(), "LoginAction()");

                action.LoginAction(this, context, assertion);

                Logger.DebugFormat("{0}.{1} finished", action.GetType(), "LoginAction()");
            }
        }

        private void TransferClient(IDPEndPoint idpEndpoint, Saml20AuthnRequest request, HttpContext context)
        {
            //Set the last IDP we attempted to login at.
            context.Session[IDPTempSessionKey]= idpEndpoint.Id;

            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            IDPEndPointElement destination = 
                DetermineEndpointConfiguration(SAMLBinding.REDIRECT, idpEndpoint.SSOEndpoint, idpEndpoint.metadata.SSOEndpoints());
    
            request.Destination = destination.Url;

            if (idpEndpoint.ForceAuthn)
                request.ForceAuthn = true;

            object isPassiveFlag = context.Session[IDPIsPassive];

            if (isPassiveFlag != null && (bool)isPassiveFlag)
            {
                request.IsPassive = true;
                context.Session[IDPIsPassive] = null;
            }

            if (idpEndpoint.IsPassive)
                request.IsPassive = true;

            object forceAuthnFlag = context.Session[IDPForceAuthn];

            if (forceAuthnFlag != null && (bool)forceAuthnFlag)
            {
                request.ForceAuthn = true;
                context.Session[IDPForceAuthn] = null;
            }

            if (idpEndpoint.SSOEndpoint != null)
            {
                if (!string.IsNullOrEmpty(idpEndpoint.SSOEndpoint.ForceProtocolBinding))
                {
                    request.ProtocolBinding = idpEndpoint.SSOEndpoint.ForceProtocolBinding;
                }
            }

            //Save request message id to session
            context.Session.Add(ExpectedInResponseToSessionKey, request.ID);

            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                Logger.DebugFormat(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Redirect, idpEndpoint.Id);
                
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = _certificate.PrivateKey;
                builder.Request = request.GetXml().OuterXml;
                string s = request.Destination + "?" + builder.ToQuery();

                Logger.Debug("Redirecting user to IdP for authentication: " + builder.Request);

                context.Response.Redirect(s, true);
                return;
            }

            if (destination.Binding == SAMLBinding.POST)
            {
                Logger.DebugFormat(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Post, idpEndpoint.Id);

                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                //Honor the ForceProtocolBinding and only set this if it's not already set
                if (string.IsNullOrEmpty(request.ProtocolBinding))
                    request.ProtocolBinding = Saml20Constants.ProtocolBindings.HTTP_Post;
                XmlDocument req = request.GetXml();
                XmlSignatureUtils.SignDocument(req, request.ID);
                builder.Request = req.OuterXml;

                Logger.Debug("Sending an AuthnRequest with POST binding");

                builder.GetPage().ProcessRequest(context);
                return;
            }

            if(destination.Binding == SAMLBinding.ARTIFACT)
            {
                Logger.DebugFormat(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Artifact, idpEndpoint.Id);

                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
                //Honor the ForceProtocolBinding and only set this if it's not already set
                if(string.IsNullOrEmpty(request.ProtocolBinding))
                    request.ProtocolBinding = Saml20Constants.ProtocolBindings.HTTP_Artifact;

                Logger.Debug("Sending an AuthnRequest with artifact binding");

                builder.RedirectFromLogin(destination, request);
            }

            HandleError(context, Resources.BindingError);
        }

    }
}
