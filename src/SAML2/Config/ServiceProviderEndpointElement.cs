using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Service Provider Endpoint configuration element.
    /// </summary>
    public class ServiceProviderEndpointElement : ConfigurationElement, IConfigurationElementCollectionElement
    {
        #region Attributes

        /// <summary>
        /// Gets the binding.
        /// </summary>
        [ConfigurationProperty("binding")]
        public BindingType Binding
        {
            get { return (BindingType)base["binding"]; }
        }

        /// <summary>
        /// Gets the index.
        /// </summary>
        [ConfigurationProperty("index")]
        public ushort Index
        {
            get { return (ushort) base["index"]; }
        }

        /// <summary>
        /// Gets the type.
        /// </summary>
        [ConfigurationProperty("localPath", IsRequired = true)]
        public string LocalPath
        {
            get { return (string) base["localPath"]; }
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
        public EndpointType Type
        {
            get { return (EndpointType)base["type"]; }
        }

        #endregion

        #region Implementation of IConfigurationElementCollectionElement

        /// <summary>
        /// Gets the element key.
        /// </summary>
        public object ElementKey
        {
            get { return Type; }
        }

        #endregion
    }
}
