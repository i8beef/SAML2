using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Identity Provider Endpoint configuration element.
    /// </summary>
    public class IdentityProviderEndpointElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the binding.
        /// </summary>
        [ConfigurationProperty("binding", IsRequired = true)]
        public string Binding
        {
            get { return (string)base["binding"]; }
        }

        /// <summary>
        /// Gets the protocol binding to force.
        /// </summary>
        [ConfigurationProperty("forceProtocolBinding")]
        public string ForceProtocolBinding
        {
            get { return (string)base["forceProtocolBinding"]; }
        }

        /// <summary>
        /// Allows the caller to access the xml representation of an assertion before it's 
        /// translated to a strongly typed instance
        /// </summary>
        [ConfigurationProperty("tokenAccessor")]
        public string TokenAccessor
        {
            get { return (string)base["tokenAccessor"]; }
        }

        /// <summary>
        /// Gets the type.
        /// </summary>
        [ConfigurationProperty("type", IsKey = true, IsRequired = true)]
        [RegexStringValidator(@"^(signon|logout)$")]
        public string Type
        {
            get { return (string)base["type"]; }
        }

        /// <summary>
        /// Gets the URL.
        /// </summary>
        [ConfigurationProperty("url", IsRequired = true)]
        public string Url
        {
            get { return (string)base["url"]; }
        }

        #endregion
    }
}
