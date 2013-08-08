using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Metadata configuration element.
    /// </summary>
    public class MetadataElement : ConfigurationElement
    {
        /// <summary>
        /// Gets a value indicating whether to exclude artifact endpoints in metadata generation.
        /// </summary>
        [ConfigurationProperty("excludeArtifactEndpoints")]
        public bool ExcludeArtifactEndpoints
        {
            get { return (bool)base["excludeArtifactEndpoints"]; }
        }
    }
}
