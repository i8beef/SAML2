using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Metadata configuration element.
    /// </summary>
    public class MetadataElement : WritableConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets or sets a value indicating whether to exclude artifact endpoints in metadata generation.
        /// </summary>
        /// <value><c>true</c> if exclude artifact endpoints; otherwise, <c>false</c>.</value>
        [ConfigurationProperty("excludeArtifactEndpoints")]
        public bool ExcludeArtifactEndpoints
        {
            get { return (bool)base["excludeArtifactEndpoints"]; }
            set { base["excludeArtifactEndpoints"] = value; }
        }

        #endregion

        #region Elements

        /// <summary>
        /// Gets or sets the contacts.
        /// </summary>
        /// <value>The contacts.</value>
        [ConfigurationProperty("contacts")]
        public ContactCollection Contacts
        {
            get { return (ContactCollection)base["contacts"]; }
            set { base["contacts"] = value; }
        }

        /// <summary>
        /// Gets or sets the organization.
        /// </summary>
        /// <value>The organization.</value>
        [ConfigurationProperty("organization")]
        public OrganizationElement Organization
        {
            get
            {
                // This makes the value of Organization be null if it is excluded in the config
                return (OrganizationElement)base[new ConfigurationProperty("organization", typeof(OrganizationElement), null)];
            }
            set { base["organization"] = value; }
        }

        #endregion
    }
}
