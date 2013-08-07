using System;
using System.Diagnostics;
using System.IO;
using System.Web;
using System.Web.Caching;
using System.Xml;
using SAML2.Config;
using SAML2.Logging;
using SAML2.Properties;
using SAML2.Schema.Protocol;
using SAML2.Utils;

namespace SAML2.Bindings
{
    /// <summary>
    /// Implementation of the artifact over HTTP SOAP binding.
    /// </summary>
    public class HttpArtifactBindingBuilder : HttpSOAPBindingBuilder
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpArtifactBindingBuilder"/> class.
        /// </summary>
        /// <param name="context">The current http context.</param>
        public HttpArtifactBindingBuilder(HttpContext context): base(context){}

        /// <summary>
        /// Creates an artifact and redirects the user to the IdP
        /// </summary>
        /// <param name="destination">The destination of the request.</param>
        /// <param name="request">The authentication request.</param>
        public void RedirectFromLogin(IdentityProviderEndpointElement destination, Saml20AuthnRequest request)
        {
            var config = Saml2Config.GetConfig();
            Int16 index = (Int16)config.ServiceProvider.Endpoints.SignOnEndpoint.Index;
            XmlDocument doc = request.GetXml();
            XmlSignatureUtils.SignDocument(doc, request.Request.ID);
            ArtifactRedirect(destination, index, doc);
        }

        /// <summary>
        /// Creates an artifact for the LogoutRequest and redirects the user to the IdP.
        /// </summary>
        /// <param name="destination">The destination of the request.</param>
        /// <param name="request">The logout request.</param>
        public void RedirectFromLogout(IdentityProviderEndpointElement destination, Saml20LogoutRequest request)
        {
            var config = Saml2Config.GetConfig();
            Int16 index = (Int16)config.ServiceProvider.Endpoints.LogoutEndpoint.Index;
            XmlDocument doc = request.GetXml();
            XmlSignatureUtils.SignDocument(doc, request.Request.ID);
            ArtifactRedirect(destination, index, doc);
        }

        /// <summary>
        /// Creates an artifact for the LogoutRequest and redirects the user to the IdP.
        /// </summary>
        /// <param name="destination">The destination of the request.</param>
        /// <param name="request">The logout request.</param>
        /// <param name="relayState">The query string relay state value to add to the communication</param>
        public void RedirectFromLogout(IdentityProviderEndpointElement destination, Saml20LogoutRequest request, string relayState)
        {
            var config = Saml2Config.GetConfig();
            Int16 index = (Int16)config.ServiceProvider.Endpoints.LogoutEndpoint.Index;
            XmlDocument doc = request.GetXml();
            XmlSignatureUtils.SignDocument(doc, request.Request.ID);
            ArtifactRedirect(destination, index, doc, relayState);
        }

        /// <summary>
        /// Creates an artifact for the LogoutResponse and redirects the user to the IdP.
        /// </summary>
        /// <param name="destination">The destination of the response.</param>
        /// <param name="response">The logout response.</param>
        public void RedirectFromLogout(IdentityProviderEndpointElement destination, Saml20LogoutResponse response)
        {
            var config = Saml2Config.GetConfig();
            Int16 index = (Int16)config.ServiceProvider.Endpoints.LogoutEndpoint.Index;
            XmlDocument doc = response.GetXml();
            XmlSignatureUtils.SignDocument(doc, response.Response.ID);

            ArtifactRedirect(destination, index, doc);
        }

        /// <summary>
        /// Handles all artifact creations and redirects.
        /// </summary>
        /// <param name="destination">The destination.</param>
        /// <param name="localEndpointIndex">Index of the local endpoint.</param>
        /// <param name="signedSamlMessage">The signed saml message.</param>
        /// <param name="relayState">The query string relay state value to add to the communication</param>
        private void ArtifactRedirect(IdentityProviderEndpointElement destination, Int16 localEndpointIndex, XmlDocument signedSamlMessage, string relayState)
        {
            var config = Saml2Config.GetConfig();
            string sourceId = config.ServiceProvider.Id;
            byte[] sourceIdHash = ArtifactUtil.GenerateSourceIdHash(sourceId);
            byte[] messageHandle = ArtifactUtil.GenerateMessageHandle();

            string artifact = ArtifactUtil.CreateArtifact(HttpArtifactBindingConstants.ArtifactTypeCode, localEndpointIndex, sourceIdHash, messageHandle);

            _context.Cache.Insert(artifact, signedSamlMessage, null, DateTime.Now.AddMinutes(1), Cache.NoSlidingExpiration);

            string destinationUrl = destination.Url + "?" + HttpArtifactBindingConstants.ArtifactQueryStringName + "=" +
                                    HttpUtility.UrlEncode(artifact);
            if (!string.IsNullOrEmpty(relayState))
            {
                destinationUrl += "&relayState=" + relayState;
            }

            if (Logger.IsDebugEnabled)
            {
                Logger.DebugFormat(Tracing.CreatedArtifact, artifact, signedSamlMessage.OuterXml);
            }

            _context.Response.Redirect(destinationUrl);
        }

        /// <summary>
        /// Handles all artifact creations and redirects. Convenience wrapper which re-uses the existing relay state
        /// </summary>
        /// <param name="destination">The destination.</param>
        /// <param name="localEndpointIndex">Index of the local endpoint.</param>
        /// <param name="signedSamlMessage">The signed saml message.</param>
        private void ArtifactRedirect(IdentityProviderEndpointElement destination, Int16 localEndpointIndex, XmlDocument signedSamlMessage)
        {
            ArtifactRedirect(destination, localEndpointIndex, signedSamlMessage, _context.Request.Params["relayState"]);
        }

        /// <summary>
        /// Handles responses to an artifact resolve message.
        /// </summary>
        /// <param name="artifactResolve">The artifact resolve message.</param>
        public void RespondToArtifactResolve(ArtifactResolve artifactResolve)
        {
            XmlDocument samlDoc = (XmlDocument)_context.Cache.Get(artifactResolve.Artifact);
            
            Saml20ArtifactResponse response = Saml20ArtifactResponse.GetDefault();
            response.StatusCode = Saml20Constants.StatusCodes.Success;
            response.InResponseTo = artifactResolve.ID;
            response.SamlElement = samlDoc.DocumentElement;

            XmlDocument responseDoc = response.GetXml();

            if (responseDoc.FirstChild is XmlDeclaration)
                responseDoc.RemoveChild(responseDoc.FirstChild);

            XmlSignatureUtils.SignDocument(responseDoc, response.ID);

            if (Logger.IsDebugEnabled)
            {
                Logger.DebugFormat(Tracing.RespondToArtifactResolve, artifactResolve.Artifact, responseDoc.OuterXml);
            }
            SendResponseMessage(responseDoc.OuterXml);
        }

        /// <summary>
        /// Resolves an artifact.
        /// </summary>
        /// <returns>A stream containing the artifact response from the IdP</returns>
        public Stream ResolveArtifact()
        {
            Logger.DebugFormat("{0}.{1} called", GetType(), "ResolveArtifact()");

            string artifact = _context.Request.Params["SAMLart"];

            IdentityProviderElement idpEndPoint = DetermineIdp(artifact);

            if (idpEndPoint == null)
                throw new InvalidOperationException("Received artifact from unknown IDP.");

            ushort endpointIndex = ArtifactUtil.GetEndpointIndex(artifact);

            string endpointUrl = idpEndPoint.Metadata.GetARSEndpoint(endpointIndex);

            Saml20ArtifactResolve resolve = Saml20ArtifactResolve.GetDefault();

            resolve.Artifact = artifact;

            XmlDocument doc = resolve.GetXml();

            if (doc.FirstChild is XmlDeclaration)
                doc.RemoveChild(doc.FirstChild);

            XmlSignatureUtils.SignDocument(doc, resolve.ID);

            string artifactResolveString = doc.OuterXml;

            Logger.DebugFormat(Tracing.ResolveArtifact, artifact, idpEndPoint.Id, endpointIndex, endpointUrl, artifactResolveString);

            return GetResponse(endpointUrl, artifactResolveString, idpEndPoint.ArtifactResolution);
            
        }

        /// <summary>
        /// Determines which IdP an artifact has been sent from.
        /// </summary>
        /// <param name="artifact">The artifact.</param>
        /// <returns>An IdP configuration element</returns>
        private IdentityProviderElement DetermineIdp(string artifact)
        {
            var config = Saml2Config.GetConfig();
            
            short typeCodeValue = -1;
            short endPointIndex = -1;
            byte[] sourceIdHash = new byte[20];
            byte[] messageHandle = new byte[20];

            if (ArtifactUtil.TryParseArtifact(artifact, ref typeCodeValue, ref endPointIndex, ref sourceIdHash, ref messageHandle))
            {
                foreach(IdentityProviderElement ep in config.IdentityProviders)
                {
                    byte[] hash = ArtifactUtil.GenerateSourceIdHash(ep.Id);
                    if (AreEqual(sourceIdHash, hash))
                        return ep;
                }
            }
            
            return null;
        }

        /// <summary>
        /// Determines if the contents of 2 byte arrays are identical
        /// </summary>
        /// <param name="a">The first array</param>
        /// <param name="b">The second array</param>
        /// <returns></returns>
        private bool AreEqual(byte[] a, byte[] b)
        {
            for(int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }

            return true;
        }

        
    }
}