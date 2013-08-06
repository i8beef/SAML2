using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Common Domain Cookie configuration element.
    /// </summary>
    public class CommonDomainCookieElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets a value indicating whether Common Domain Cookie is enabled.
        /// </summary>
        [ConfigurationProperty("enabled")]
        public bool Enabled
        {
            get { return (bool)base["enabled"]; }
        }

        /// <summary>
        /// Gets the local reader endpoint.
        /// </summary>
        [ConfigurationProperty("localReaderEndpoint")]
        public string LocalReaderEndpoint
        {
            get { return (string)base["localReaderEndpoint"]; }
        }

        #endregion
    }
}
