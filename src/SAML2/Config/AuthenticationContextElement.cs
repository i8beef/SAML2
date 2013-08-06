using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Authentication Context configuration element.
    /// </summary>
    public class AuthenticationContextElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the authentication context.
        /// </summary>
        [ConfigurationProperty("context", IsKey = true, IsRequired = true)]
        public string Context
        {
            get { return (string)base["context"]; }
        }

        /// <summary>
        /// Gets the type of the reference.
        /// </summary>
        [ConfigurationProperty("referenceType", IsRequired = true)]
        public string ReferenceType
        {
            get { return (string)base["referenceType"]; }
        }

        #endregion
    }
}
