using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Identity Provider configuration element.
    /// </summary>
    public class IdentityProviderElement : ConfigurationElement, IConfigurationElementCollectionElement
    {
        /// <summary>
        /// Gets or sets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        public Saml20MetadataDocument Metadata { get; set; }

        #region Attributes

        /// <summary>
        /// Gets a value indicating whether this <see cref="IdentityProviderElement"/> is default.
        /// </summary>
        /// <remarks>
        /// Use default in case common domain cookie is not set, and more than one endpoint is available.
        /// </remarks>
        [ConfigurationProperty("default")]
        public bool Default
        {
            get { return (bool)base["default"]; }
            set { base["default"] = value; }
        }

        /// <summary>
        /// Gets a value indicating whether to force authentication on each AuthnRequest.
        /// </summary>
        [ConfigurationProperty("forceAuth")]
        public bool ForceAuth
        {
            get { return (bool)base["forceAuth"]; }
            set { base["forceAuth"] = value; }
        }

        /// <summary>
        /// Gets the id.
        /// </summary>
        [ConfigurationProperty("id", IsKey = true, IsRequired = true)]
        public string Id
        {
            get { return (string)base["id"]; }
            set { base["id"] = value; }
        }

        /// <summary>
        /// Gets a value indicating whether this AuthnRequest should be passive.
        /// </summary>
        [ConfigurationProperty("isPassive")]
        public bool IsPassive
        {
            get { return (bool)base["isPassive"]; }
            set { base["isPassive"] = value; }
        }

        /// <summary>
        /// Gets the name.
        /// </summary>
        [ConfigurationProperty("name")]
        public string Name
        {
            get { return (string)base["name"]; }
            set { base["name"] = value; }
        }

        /// <summary>
        /// Gets a value indicating whether to omit assertion signature check.
        /// </summary>
        [ConfigurationProperty("omitAssertionSignatureCheck")]
        public bool OmitAssertionSignatureCheck
        {
            get { return (bool)base["omitAssertionSignatureCheck"]; }
            set { base["omitAssertionSignatureCheck"] = value; }
        }

        /// <summary>
        /// Gets a value indicating whether to enable quirks mode.
        /// </summary>
        [ConfigurationProperty("quirksMode")]
        public bool QuirksMode
        {
            get { return (bool)base["quirksMode"]; }
            set { base["quirksMode"] = value; }
        }

        /// <summary>
        /// Override option for the default UTF-8 encoding convention on SAML responses
        /// </summary>
        [ConfigurationProperty("responseEncoding")]
        public string ResponseEncoding
        {
            get { return (string)base["responseEncoding"]; }
            set { base["responseEncoding"] = value; }
        }

        #endregion

        #region Elements

        /// <summary>
        /// Gets the artifact resolution.
        /// </summary>
        [ConfigurationProperty("artifactResolution")]
        public HttpBasicAuthElement ArtifactResolution
        {
            get { return (HttpBasicAuthElement)base["artifactResolution"]; }
        }

        /// <summary>
        /// Gets the attribute query configuration parameters.
        /// </summary>
        [ConfigurationProperty("attributeQuery")]
        public HttpBasicAuthElement AttributeQuery
        {
            get { return (HttpBasicAuthElement)base["attributeQuery"]; }
        }
        
        /// <summary>
        /// Gets the certificate validation.
        /// </summary>
        [ConfigurationProperty("certificateValidations")]
        public CertificateValidationCollection CertificateValidations
        {
            get { return (CertificateValidationCollection)base["certificateValidations"]; }
        }

        /// <summary>
        /// Gets the common domain cookie configuration settings.
        /// </summary>
        [ConfigurationProperty("commonDomainCookie")]
        public KeyValueConfigurationCollection CommonDomainCookie
        {
            get { return (KeyValueConfigurationCollection)base["commonDomainCookie"]; }
        }

        /// <summary>
        /// Gets the endpoints.
        /// </summary>
        [ConfigurationProperty("endpoints")]
        public IdentityProviderEndpointCollection Endpoints
        {
            get { return (IdentityProviderEndpointCollection)base["endpoints"]; }
        }

        /// <summary>
        /// Gets the persistent pseudonym configuration settings.
        /// </summary>
        [ConfigurationProperty("persistentPseudonym")]
        public PersistentPseudonymElement PersistentPseudonym
        {
            get { return (PersistentPseudonymElement)base["persistentPseudonym"]; }
        }

        #endregion

        #region Implementation of IConfigurationElementCollectionElement

        /// <summary>
        /// Gets the element key.
        /// </summary>
        public object ElementKey
        {
            get { return Id; }
        }

        #endregion
    }
}
