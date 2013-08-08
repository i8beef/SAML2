using System;
using System.IO;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using System.Xml;

namespace SAML2.Bindings
{
    /// <summary>
    /// Parses the response messages related to the artifact binding.
    /// </summary>
    public class HttpArtifactBindingParser : HttpSoapBindingParser
    {
        /// <summary>
        /// The artifact resolve.
        /// </summary>
        private ArtifactResolve _artifactResolve;

        /// <summary>
        /// The artifact response.
        /// </summary>
        private ArtifactResponse _artifactResponse;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpArtifactBindingParser"/> class.
        /// </summary>
        /// <param name="inputStream">The input stream.</param>
        public HttpArtifactBindingParser(Stream inputStream): base(inputStream) {}

        /// <summary>
        /// Gets the artifact resolve message.
        /// </summary>
        /// <value>The artifact resolve.</value>
        public ArtifactResolve ArtifactResolve
        {
            get
            {
                if (!IsArtifactResolve)
                {
                    throw new InvalidOperationException("The Saml message is not an ArtifactResolve");
                }
                LoadArtifactResolve();

                return _artifactResolve;
            }
        }

        /// <summary>
        /// Gets the artifact response message.
        /// </summary>
        /// <value>The artifact response.</value>
        public ArtifactResponse ArtifactResponse
        {
            get
            {
                if (!IsArtifactResponse)
                {
                    throw new InvalidOperationException("The Saml message is not an ArtifactResponse");
                }
                LoadArtifactResponse();

                return _artifactResponse;
            }
        }


        /// <summary>
        /// Gets a value indicating whether this instance is artifact resolve.
        /// </summary>
        public bool IsArtifactResolve
        {
            get { return SamlMessage.LocalName == HttpArtifactBindingConstants.ArtifactResolve; }
        }

        /// <summary>
        /// Gets a value indicating whether this instance is artifact response.
        /// </summary>
        public bool IsArtifactResponse
        {
            get { return SamlMessage.LocalName == HttpArtifactBindingConstants.ArtifactResponse; }
        }

        /// <summary>
        /// Gets the issuer of the current message.
        /// </summary>
        /// <value>The issuer.</value>
        public string Issuer
        {
            get
            {
                if (IsArtifactResolve)
                {
                    return ArtifactResolve.Issuer.Value;
                }

                if (IsArtifactResponse)
                {
                    return ArtifactResponse.Issuer.Value;
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Loads the current message as an artifact resolve.
        /// </summary>
        private void LoadArtifactResolve()
        {
            if (_artifactResolve == null)
            {
                _artifactResolve = Serialization.Deserialize<ArtifactResolve>(new XmlNodeReader(SamlMessage));
            }
        }

        /// <summary>
        /// Loads the current message as an artifact response.
        /// </summary>
        private void LoadArtifactResponse()
        {
            if (_artifactResponse == null)
            {
                _artifactResponse = Serialization.Deserialize<ArtifactResponse>(new XmlNodeReader(SamlMessage));
            }
        }
    }
}