using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Persistent Pseudonym configuration element.
    /// </summary>
    public class PersistentPseudonymElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the mapper.
        /// </summary>
        [ConfigurationProperty("mapper")]
        public string Mapper
        {
            get { return (string)base["mapper"]; }
        }

        #endregion
    }
}
