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

        #endregion
    }
}
