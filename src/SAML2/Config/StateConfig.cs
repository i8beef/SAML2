using System.Collections.Generic;

namespace SAML2.Config
{
    /// <summary>
    /// State configuration element.
    /// </summary>
    public class StateConfig
    {
        public StateConfig()
        {
            Settings = new Dictionary<string, string>();
        }

        /// <summary>
        /// Gets or sets the state service factory.
        /// </summary>
        /// <value>The logging factory.</value>
        public string StateServiceFactory { get; set; }

        /// <summary>
        /// Gets or sets the settings.
        /// </summary>
        /// <value>The settings.</value>
        public IDictionary<string, string> Settings { get; set; }
    }
}
