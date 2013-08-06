using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// ServiceProvider configuration element.
    /// </summary>
    public class ServiceProviderElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the id.
        /// </summary>
        [ConfigurationProperty("id", IsRequired = true)]
        public string Id
        {
            get { return (string)base["id"]; }
        }

        /// <summary>
        /// Gets the server.
        /// </summary>
        [ConfigurationProperty("server", IsRequired = true)]
        public string Server
        {
            get { return (string)base["server"]; }
        }

        #endregion

        #region Elements

        /// <summary>
        /// Gets the authentication contexts.
        /// </summary>
        [ConfigurationProperty("authenticationContexts")]
        public AuthenticationContextCollection AuthenticationContexts
        {
            get { return (AuthenticationContextCollection)base["authenticationContexts"]; }
        }

        /// <summary>
        /// Gets the contacts.
        /// </summary>
        [ConfigurationProperty("contacts")]
        public ContactCollection Contacts
        {
            get { return (ContactCollection)base["contacts"]; }
        }

        /// <summary>
        /// Gets the endpoints.
        /// </summary>
        [ConfigurationProperty("endpoints", Options = ConfigurationPropertyOptions.IsRequired)]
        public ServiceProviderEndpointCollection Endpoints
        {
            get { return (ServiceProviderEndpointCollection) base["endpoints"]; }
        }

        /// <summary>
        /// Gets the name id formats.
        /// </summary>
        [ConfigurationProperty("nameIdFormats")]
        public NameIdFormatCollection NameIdFormats
        {
            get { return (NameIdFormatCollection)base["nameIdFormats"]; }
        }

        /// <summary>
        /// Gets the organization.
        /// </summary>
        [ConfigurationProperty("organization")]
        public OrganizationElement Organization
        {
            get { return (OrganizationElement)base["organization"]; }            
        }

        /// <summary>
        /// Gets the organization.
        /// </summary>
        [ConfigurationProperty("signingCertificate")]
        public SigningCertificateElement SigningCertificate
        {
            get { return (SigningCertificateElement)base["signingCertificate"]; }
        }

        #endregion
    }
}
