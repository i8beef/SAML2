using System;
using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Service Provider Endpoint configuration collection.
    /// </summary>
    [ConfigurationCollection(typeof (AuthenticationContextElement), CollectionType = ConfigurationElementCollectionType.AddRemoveClearMap)]
    public class AuthenticationContextCollection : ConfigurationElementCollection
    {
        /// <summary>
        /// Gets the comparison.
        /// </summary>
        [ConfigurationProperty("comparison", DefaultValue = AuthenticationContextComparison.Exact)]
        public AuthenticationContextComparison Comparison
        {
            get { return (AuthenticationContextComparison)base["comparison"]; }
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
            return new AuthenticationContextElement();
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

            return ((AuthenticationContextElement) element).Context;
        }

        #endregion
    }
}
