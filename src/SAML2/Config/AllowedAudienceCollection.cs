using System;
using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Allows Audience configuration element.
    /// </summary>
    [ConfigurationCollection(typeof(AudienceElement), AddItemName = "audience", CollectionType = ConfigurationElementCollectionType.AddRemoveClearMap)]
    public class AllowedAudienceCollection : ConfigurationElementCollection
    {
        #region Overrides of ConfigurationElementCollection

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new AudienceElement();
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

            return ((AudienceElement)element).Uri;
        }

        #endregion
    }
}
