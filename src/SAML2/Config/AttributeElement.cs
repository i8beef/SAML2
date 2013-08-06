using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Attribute configuration element.
    /// </summary>
    public class AttributeElement : ConfigurationElement
    {
        /// <summary>
        /// Gets a value indicating whether this attribute is required.
        /// </summary>
        [ConfigurationProperty("isRequired", IsRequired = true)]
        public bool IsRequired
        {
            get { return (bool) base["isRequired"]; }
        }

        /// <summary>
        /// Gets the name.
        /// </summary>
        [ConfigurationProperty("name", IsRequired = true)]
        public string Name
        {
            get { return (string) base["name"]; }
        }
    }
}
