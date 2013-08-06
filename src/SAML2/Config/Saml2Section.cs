using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// SAML2 Configuration Section.
    /// </summary>
    public class Saml2Section : ConfigurationSection
    {
        /// <summary>
        /// Gets the allowed audience uris.
        /// </summary>
        [ConfigurationProperty("allowedAudiences")]
        public AllowedAudienceCollection AllowedAudiences
        {
            get { return (AllowedAudienceCollection) base["allowedAudiences"]; }
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
    }
}
