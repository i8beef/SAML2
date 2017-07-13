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

        public static void Init(ISaml2ConfigProvider configProvider)
        {
            _config = configProvider.SAML2Config;
        }
        public static void ReloadIdentityProvider(ISaml2ConfigProvider configProvider)
        {
            _config = configProvider.SAML2Config;
            _config.IdentityProviders.Refresh();
        }

        /// <summary>
        /// Gets the config.
        /// </summary>
        /// <returns>The <see cref="Saml2Section"/> config.</returns>
        public static Saml2Section GetConfig()
        {
            if (_config == null)
            {
                _config = ConfigurationManager.GetSection(Saml2Section.Name) as Saml2Section;

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
