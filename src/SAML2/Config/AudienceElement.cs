using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Audience configuration element.
    /// </summary>
    public class AudienceElement : ConfigurationElement
    {
        /// <summary>
        /// Gets the URI.
        /// </summary>
        [ConfigurationProperty("uri", IsKey = true, IsRequired = true)]
        public string Uri
        {
            get { return (string) base["uri"]; }
        }
    }
}
