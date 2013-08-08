using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Attribute configuration element.
    /// </summary>
    public class AttributeElement : ConfigurationElement, IConfigurationElementCollectionElement
    {
        #region Attributes

        /// <summary>
        /// Gets a value indicating whether this attribute is required.
        /// </summary>
        [ConfigurationProperty("isRequired")]
        public bool IsRequired
        {
            get { return (bool) base["isRequired"]; }
        }

        /// <summary>
        /// Gets the name.
        /// </summary>
        [ConfigurationProperty("name", IsKey = true, IsRequired = true)]
        public string Name
        {
            get { return (string) base["name"]; }
        }

        #endregion

        #region Implementation of IConfigurationElementCollectionElement

        /// <summary>
        /// Gets the element key.
        /// </summary>
        public object ElementKey
        {
            get { return Name; }
        }

        #endregion
    }
}
