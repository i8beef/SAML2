using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Assertion Profile configuration element.
    /// </summary>
    public class AssertionProfileElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the assertion validator.
        /// </summary>
        [ConfigurationProperty("assertionValidator", IsRequired = true)]
        public string AssertionValidator
        {
            get { return (string)base["assertionValidator"]; }
        }

        #endregion
    }
}
