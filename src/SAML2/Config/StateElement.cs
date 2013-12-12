using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// State configuration element.
    /// </summary>
    public class StateElement : WritableConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets or sets the state service factory.
        /// </summary>
        /// <value>The logging factory.</value>
        [ConfigurationProperty("stateServiceFactory")]
        public string StateServiceFactory { get { return (string)base["stateServiceFactory"]; } set { base["stateServiceFactory"] = value; } }

        /// <summary>
        /// Gets or sets the settings.
        /// </summary>
        /// <value>The settings.</value>
        [ConfigurationProperty("settings")]
        public StateSettingCollection Settings
        {
            get { return (StateSettingCollection)base["settings"]; }
            set { base["settings"] = value; }
        }

        #endregion
    }
}
