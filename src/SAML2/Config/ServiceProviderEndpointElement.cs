using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Service Provider Endpoint configuration element.
    /// </summary>
    public class ServiceProviderEndpointElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the type.
        /// </summary>
        [ConfigurationProperty("localPath", IsRequired = true)]
        public string LocalPath
        {
            get { return (string)base["localPath"]; }
        }

        /// <summary>
        /// Gets the redirect URL.
        /// </summary>
        [ConfigurationProperty("redirectUrl")]
        public string RedirectUrl
        {
            get { return (string)base["redirectUrl"]; }
        }

        /// <summary>
        /// Gets the type.
        /// </summary>
        [ConfigurationProperty("type", IsKey = true, IsRequired = true)]
        [RegexStringValidator(@"^(signon|logout|metadata)$")]
        public string Type
        {
            get { return (string) base["type"]; }
        }

        #endregion
    }
}
