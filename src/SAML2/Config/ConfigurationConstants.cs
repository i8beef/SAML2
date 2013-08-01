namespace SAML2.Config
{
    /// <summary>
    /// The common location for all configuration-section related constants
    /// </summary>
    public class ConfigurationConstants
    {
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
