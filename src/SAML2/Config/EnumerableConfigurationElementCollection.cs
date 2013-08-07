using System;
using System.Collections.Generic;
using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Enumerable ConfigurationElementCollection abstract base class.
    /// </summary>
    /// <typeparam name="TConfigurationElementType">The type of the configuration element type.</typeparam>
    public abstract class EnumerableConfigurationElementCollection<TConfigurationElementType> :
        ConfigurationElementCollection, IEnumerable<TConfigurationElementType>
        where TConfigurationElementType : ConfigurationElement, IConfigurationElementCollectionElement, new()
    {
        /// <summary>
        /// Gets or sets a property, attribute, or child element of this configuration element.
        /// </summary>
        /// <returns>
        /// The specified property, attribute, or child element
        /// </returns>
        /// <exception cref="T:System.Configuration.ConfigurationErrorsException" />
        public TConfigurationElementType this[int index]
        {
            get { return (TConfigurationElementType)BaseGet(index); }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        #region Implementation of IEnumerable<TConfigurationElementType>

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Collections.Generic.IEnumerator`1"/> that can be used to iterate through the collection.
        /// </returns>
        /// <filterpriority>1</filterpriority>
        public new IEnumerator<TConfigurationElementType> GetEnumerator()
        {
            foreach (var type in this)
            {
                yield return type;
            }
        }

        #endregion

        #region Overrides of ConfigurationElementCollection

        /// <summary>
        /// When overridden in a derived class, creates a new <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </summary>
        /// <returns>
        /// A new <see cref="T:System.Configuration.ConfigurationElement"/>.
        /// </returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new TConfigurationElementType();
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

            return ((TConfigurationElementType)element).ElementKey;
        }

        #endregion
    }
}

