using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Reflection;

namespace SAML2.Config
{
    /// <summary>
    /// Provides helper methods for getting the configuration.
    /// </summary>
    public static class Saml2Config
    {
        /// <summary>
        /// The configuration
        /// </summary>
        private static Saml2Section _config;

        private static SAML2AbstractConfigProvider ConfigProvider
        {
            get;
            set;
        }

        public static void Init(SAML2AbstractConfigProvider configProvider)
        {
            ConfigProvider = configProvider;
        }

        /// <summary>
        /// Gets the config.
        /// </summary>
        /// <returns>The <see cref="Saml2Section"/> config.</returns>
        public static Saml2Section GetConfig()
        {
            if (_config == null)
            {
                if (ConfigProvider == null)
                {
                    _config = ConfigurationManager.GetSection(Saml2Section.Name) as Saml2Section;
                }
                else
                {
                    _config = ConfigProvider.SAML2Config;
                }

                if (_config == null)
                {
                    throw new ConfigurationErrorsException(string.Format("Configuration section \"{0}\" not found", typeof(Saml2Section).Name));
                }

                _config.IdentityProviders.Refresh();
            }

            return _config;
        }
    }
}
