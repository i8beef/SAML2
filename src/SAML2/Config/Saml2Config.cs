using System.Configuration;
using System.IO;

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
        private const string PATH = "~/SAML2.config";

        /// <summary>
        /// Gets the config.
        /// </summary>
        /// <returns>The <see cref="Saml2Section"/> config.</returns>
        public static Saml2Section GetConfig()
        {
            if (_config == null)
            {
                if (!TryLoadConfig(PATH, out _config))
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
            if (!TryLoadConfig(PATH, out _config))
            {
                throw new ConfigurationErrorsException(string.Format("Configuration section \"{0}\" not found", typeof(Saml2Section).Name));
            }

            _config.IdentityProviders.Refresh();
        }

        private static bool TryLoadConfig(string path, out Saml2Section config)
        {
            config = null;
            ExeConfigurationFileMap fileMap = new ExeConfigurationFileMap();
            string physicalWebAppPath = System.Web.Hosting.HostingEnvironment.MapPath(path);

            if (System.IO.File.Exists(physicalWebAppPath))
            {
                fileMap.ExeConfigFilename = physicalWebAppPath;
                Configuration configFile = ConfigurationManager.OpenMappedExeConfiguration(fileMap, ConfigurationUserLevel.None);
                ConfigurationManager.RefreshSection(Saml2Section.Name);
                config = configFile.GetSection(Saml2Section.Name) as Saml2Section;
                return true;
            }
            return false;
        }
    }
}
