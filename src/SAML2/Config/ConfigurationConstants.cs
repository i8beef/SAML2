namespace SAML2.config
{
    /// <summary>
    /// The common location for all configuration-section related constants
    /// </summary>
    public class ConfigurationConstants
    {
        /// <summary>
        /// We intend to use the same namespace uri for ALL configuration elements to make
        /// reuse of subelements (eg Certificate) easy.
        /// </summary>
        public const string NamespaceUri = "urn:SAML2.configuration";

        /// <summary>
        /// Section names used in configuration files.
        /// </summary>
        public sealed class SectionNames
        {            
            /// <summary>
            /// Element name for the &lt;Federation&gt; element in the configuration file.
            /// </summary>
            public const string Federation = "Federation";

            /// <summary>
            /// Element name for the &lt;SAML20Federation&gt; element in the configuration file.
            /// </summary>
            public const string SAML20Federation = "SAML20Federation";                                                
        }
    }
}
