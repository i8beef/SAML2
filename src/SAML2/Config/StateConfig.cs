using System.Collections.Generic;

namespace SAML2.Config
{
    /// <summary>
    /// State config item.
    /// </summary>
    public class StateConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="StateConfig"/> class.
        /// </summary>
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
