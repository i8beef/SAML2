using System;
using System.Xml;
using SAML2;
using SAML2.Config;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using Saml2.Properties;

namespace SAML2
{
    /// <summary>
    /// Encapsulates the ArtifactResolve schema class.
    /// </summary>
    public class Saml20ArtifactResolve
    {
        private readonly ArtifactResolve _artifactResolve;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20ArtifactResolve"/> class.
        /// </summary>
        public Saml20ArtifactResolve()
        {
            _artifactResolve = new ArtifactResolve();
            _artifactResolve.Version = Saml20Constants.Version;
            _artifactResolve.ID = "id" + Guid.NewGuid().ToString("N");
            _artifactResolve.Issuer = new NameID();
            _artifactResolve.IssueInstant = DateTime.Now;
        }

        /// <summary>
        /// Gets the underlying schema instance.
        /// </summary>
        /// <value>The resolve.</value>
        public ArtifactResolve Resolve
        {
            get
            {
                return _artifactResolve;
            }
        }

        /// <summary>
        /// Gets the ID of the SAML message.
        /// </summary>
        /// <value>The ID.</value>
        public string ID
        {
            get { return _artifactResolve.ID; }
        }

        /// <summary>
        /// Gets or sets the artifact string.
        /// </summary>
        /// <value>The artifact string.</value>
        public string Artifact
        {
            get { return _artifactResolve.Artifact; }
            set { _artifactResolve.Artifact = value; }
        }

        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        /// <value>The issuer.</value>
        public string Issuer
        {
            get { return _artifactResolve.Issuer.Value; }
            set { _artifactResolve.Issuer.Value = value; }
        }

        /// <summary>
        /// Returns the ArtifactResolve as an XML document.
        /// </summary>
        public XmlDocument GetXml()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(Serialization.SerializeToXmlString(_artifactResolve));
            return doc;
        }

        /// <summary>
        /// Gets a default instance of this class with proper values set.
        /// </summary>
        /// <returns></returns>
        public static Saml20ArtifactResolve GetDefault()
        {
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            if (config.ServiceProvider == null || string.IsNullOrEmpty(config.ServiceProvider.ID))
                throw new Saml20FormatException(Resources.ServiceProviderNotSet);

            Saml20ArtifactResolve result = new Saml20ArtifactResolve();
            result.Issuer = config.ServiceProvider.ID;

            return result;
        }
    }
}