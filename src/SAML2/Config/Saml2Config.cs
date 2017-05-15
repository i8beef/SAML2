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
    public class Saml2Config
    {
        /// <summary>
        /// The configuration
        /// </summary>
        private static Saml2Section _config;

        /// <summary>
        /// Gets the config.
        /// </summary>
        /// <returns>The <see cref="Saml2Section"/> config.</returns>
        public static Saml2Section GetConfig()
        {
            if (_config == null)
            {
                if (!TryLoadConfig(out _config))
                {
                    throw new ConfigurationErrorsException(string.Format("Configuration section \"{0}\" not found", typeof(Saml2Section).Name));
                }

                _config.IdentityProviders.Refresh();
            }

            return _config;
        }

        /// <summary>
        /// Refreshes the configuration section, so that next time it is read it is retrieved from the configuration file.
        /// </summary>
        public static void Refresh()
        {
            if (!TryLoadConfig(out _config))
            {
                throw new ConfigurationErrorsException(string.Format("Configuration section \"{0}\" not found", typeof(Saml2Section).Name));
            }

            _config.IdentityProviders.Refresh();
        }

        private static bool TryLoadConfig(out Saml2Section config)
        {
            config = null;
            
            var iconfigProviderType = typeof(ISaml2ConfigProvider);
            Assembly entryAssembly = Assembly.GetEntryAssembly();
            Type configProviderType = entryAssembly == null ? Type.GetType("Firefly.DirectoryProvider.SAML.SAMLAction, Firefly") 
                : entryAssembly
                .GetTypes()
                .Where(t => iconfigProviderType.IsAssignableFrom(t))
                .SingleOrDefault();

            if (configProviderType != null)
            {
                var provider = (ISaml2ConfigProvider)Activator.CreateInstance(configProviderType);
                config = provider.Saml2Section;
                return true;
            }
            return false;
        }
    }
}
