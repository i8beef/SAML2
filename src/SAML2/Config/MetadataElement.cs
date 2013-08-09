using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Metadata configuration element.
    /// </summary>
    public class MetadataElement : WritableConfigurationElement
    {
        /// <summary>
        /// Gets or sets a value indicating whether to exclude artifact endpoints in metadata generation.
        /// </summary>
        /// <value><c>true</c> if exclude artifact endpoints; otherwise, <c>false</c>.</value>
        [ConfigurationProperty("excludeArtifactEndpoints")]
        public bool ExcludeArtifactEndpoints
        {
            get { return (bool)base["excludeArtifactEndpoints"]; }
            set { base["excludeArtifactEndpoints"] = value; }
        }
    }
}
