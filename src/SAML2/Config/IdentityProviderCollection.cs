using System;
using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Identity Provider configuration collection.
    /// </summary>
    [ConfigurationCollection(typeof(IdentityProviderElement), CollectionType = ConfigurationElementCollectionType.AddRemoveClearMap)]
    public class IdentityProviderCollection : ConfigurationElementCollection
    {
        /// <summary>
        /// Gets the metadata location.
        /// </summary>
        [ConfigurationProperty("metadata")]
        public string MetadataLocation
        {
            get { return (string)base["metadata"]; }
        }

        #region Overrides of ConfigurationElementCollection

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new IdentityProviderElement();
        }

        /// <summary>
        /// Gets the element key for a specified configuration element when overridden in a derived class.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Object"/> that acts as the key for the specified <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </returns>
        /// <param name="element">The <see cref="T:System.Configuration.ConfigurationElement"/> to return the key for.</param>
        protected override object GetElementKey(ConfigurationElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException("element");
            }

            return ((IdentityProviderElement)element).Id;
        }

        #endregion
    }
}
