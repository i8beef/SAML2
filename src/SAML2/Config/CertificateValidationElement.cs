using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Certificate Validation configuration element.
    /// </summary>
    public class CertificateValidationElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the type.
        /// </summary>
        [ConfigurationProperty("type")]
        public string Type
        {
            get { return (string)base["type"]; }
        }

        #endregion
    }
}
