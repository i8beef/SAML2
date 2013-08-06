using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Organization configuration element.
    /// </summary>
    public class OrganizationElement : ConfigurationElement
    {
        /// <summary>
        /// Gets the display name.
        /// </summary>
        [ConfigurationProperty("displayName")]
        public string DisplayName
        {
            get { return (string)base["displayName"]; }
        }

        /// <summary>
        /// Gets the name.
        /// </summary>
        [ConfigurationProperty("name", IsRequired = true)]
        public string Name
        {
            get { return (string)base["name"]; }
        }

        /// <summary>
        /// Gets the URL.
        /// </summary>
        [ConfigurationProperty("url")]
        public string Url
        {
            get { return (string)base["url"]; }
        }

    }
}
