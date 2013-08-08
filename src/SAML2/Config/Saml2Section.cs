using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// SAML2 Configuration Section.
    /// </summary>
    public class Saml2Section : ConfigurationSection
    {
        /// <summary>
        /// The section name.
        /// </summary>
        public static string Name = "saml2";

        /// <summary>
        /// Gets a value indicating whether the <see cref="T:System.Configuration.ConfigurationElement"/> object is read-only.
        /// </summary>
        /// <returns>true if the <see cref="T:System.Configuration.ConfigurationElement"/> object is read-only; otherwise, false.</returns>
        public override bool IsReadOnly()
        {
            return false;
        }

        #region Elements

        /// <summary>
        /// Gets the actions to perform on successful processing.
        /// </summary>
        [ConfigurationProperty("actions")]
        public ActionCollection Actions
        {
            get { return (ActionCollection)base["actions"]; }
        }

        /// <summary>
        /// Gets the allowed audience uris.
        /// </summary>
        [ConfigurationProperty("allowedAudienceUris")]
        public AllowedAudienceUriCollection AllowedAudienceUris
        {
            get { return (AllowedAudienceUriCollection) base["allowedAudienceUris"]; }
            set { base["allowedAudienceUris"] = value; }
        }

        [ConfigurationProperty("assertionProfile")]
        public AssertionProfileElement AssertionProfile
        {
            get { return (AssertionProfileElement)base["assertionProfile"]; }
        }

        /// <summary>
        /// Gets the common domain cookie configuration.
        /// </summary>
        [ConfigurationProperty("commonDomainCookie")]
        public CommonDomainCookieElement CommonDomainCookie
        {
            get { return (CommonDomainCookieElement) base["commonDomainCookie"]; }
        }

        /// <summary>
        /// Gets the identity providers.
        /// </summary>
        [ConfigurationProperty("identityProviders")]
        public IdentityProviderCollection IdentityProviders
        {
            get { return (IdentityProviderCollection) base["identityProviders"]; }
        }

        /// <summary>
        /// Gets the logging configuration.
        /// </summary>
        [ConfigurationProperty("logging")]
        public LoggingElement Logging
        {
            get { return (LoggingElement) base["logging"]; }
        }

        /// <summary>
        /// Gets the metadata.
        /// </summary>
        [ConfigurationProperty("metadata")]
        public MetadataElement Metadata
        {
            get { return (MetadataElement)base["metadata"]; }
        }

        /// <summary>
        /// Gets the requested attributes.
        /// </summary>
        [ConfigurationProperty("requestedAttributes")]
        public RequestedAttributesCollection RequestedAttributes
        {
            get { return (RequestedAttributesCollection)base["requestedAttributes"]; }            
        }

        /// <summary>
        /// Gets the service provider.
        /// </summary>
        [ConfigurationProperty("serviceProvider")]
        public ServiceProviderElement ServiceProvider
        {
            get { return (ServiceProviderElement)base["serviceProvider"]; }
        }

        /// <summary>
        /// Gets a value indicating whether to show errors, or a default error message.
        /// </summary>
        [ConfigurationProperty("showError")]
        public bool ShowError
        {
            get { return (bool)base["showError"]; }
        }

        #endregion
    }
}
