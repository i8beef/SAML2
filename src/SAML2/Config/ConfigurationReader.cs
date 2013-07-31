using System;
using System.Collections.Generic;
using System.Configuration;
using System.Xml;
using System.Xml.Serialization;
using System.Text;

namespace SAML2.Config
{
    /// <summary>
    /// </summary>
    public class ConfigurationReader : ConfigurationSection
    {
        private object _currentConfig;
        private static Type _currentConfigType;

        /// <summary>
        /// Reads XML from the configuration file.
        /// </summary>
        /// <param name="reader">The <see cref="T:System.Xml.XmlReader"/> that reads from the configuration file.</param>
        /// <param name="serializeCollectionKey">true to serialize only the collection key properties; otherwise, false.</param>
        /// <exception cref="T:System.Configuration.ConfigurationErrorsException">The element to read is locked.- or -An attribute of the current node is not recognized.- or -The lock status of the current node cannot be determined.  </exception>
        protected override void DeserializeElement(XmlReader reader, bool serializeCollectionKey)
        {
            XmlSerializer serializer = new XmlSerializer(_currentConfigType);
            _currentConfig = serializer.Deserialize(reader);
        }

        /// <summary>
        /// Retrieves the contained object from the section.
        /// </summary>
        /// <returns>The contained data object.</returns>
        protected override object GetRuntimeObject()
        {
            return _currentConfig;
        }

        /// <summary>
        /// Gets an instance of the runtime class implements a configuration section.
        /// </summary>
        /// <typeparam name="ConfigType">The type of the config type.</typeparam>
        /// <returns></returns>
        public static ConfigType GetConfig<ConfigType>() where ConfigType:class
        {
            string sectionName = GetConfigSectionName(typeof (ConfigType));

            lock (typeof(ConfigurationReader))
            {
                _currentConfigType = typeof(ConfigType);
                ConfigType result = ConfigurationManager.GetSection(sectionName) as ConfigType;
                return result;
            }            
        }        

        /// <summary>
        /// Refreshes the configuration section, so that next time it is read it is retrieved from the configuration file.
        /// </summary>
        public static void RefreshConfig<ConfigType>()
        {
            string sectionName = GetConfigSectionName(typeof (ConfigType));
            ConfigurationManager.RefreshSection(sectionName);
        }

        /// <summary>
        /// Retrieve the name of the configuration section that matches the type.
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        private static string GetConfigSectionName(Type t)
        {
            // get the root attribute from the supplied type - it defines the section name
            object[] attributes = t.GetCustomAttributes(typeof(XmlRootAttribute), false);
            if (attributes.Length == 0)
                throw new ArgumentException(string.Format("Configurationtype {0} is not serializable", t.Name));

            XmlRootAttribute rootAttribute = (XmlRootAttribute)attributes[0];
            return rootAttribute.ElementName;
        }

        /// <summary>
        /// Updates a configuration section.
        /// </summary>
        /// <typeparam name="ConfigType">The type of the config type.</typeparam>
        /// <returns></returns>
        public static void SetConfig<ConfigType>(ConfigType section, Configuration config)
        {
            string sectionName = GetConfigSectionName(typeof(ConfigType));

            lock (typeof(ConfigurationReader))
            {
                _currentConfigType = typeof(ConfigType);
                ConfigurationReader configurationReader = new ConfigurationReader();
                configurationReader._currentConfig = section;
                configurationReader.SectionInformation.ForceSave = true;

                config.Sections.Remove(sectionName);
                config.Sections.Add(sectionName, configurationReader);
            }
        }        

        /// <summary>
        /// Serializes the configuration section to an XML string.
        /// Called by .NET Runtime when updating configuration.
        /// </summary>
        /// <param name="parentElement">The parent element of this section.</param>
        /// <param name="name">The name of the section.</param>
        /// <param name="saveMode">The mode to use when saving.</param>
        /// <returns></returns>
        protected override string SerializeSection(ConfigurationElement parentElement, string name, ConfigurationSaveMode saveMode)
        {
            StringBuilder str = new StringBuilder();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.OmitXmlDeclaration = true;
            XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
            ns.Add(string.Empty, ConfigurationConstants.NamespaceUri);
            using (XmlWriter xml = XmlWriter.Create(str, settings))
            {
                XmlSerializer ser = new XmlSerializer(_currentConfig.GetType());
                ser.Serialize(xml, _currentConfig, ns);
            }

            return str.ToString();
        }
    }

    /// <summary>
    /// Base class for configuration reader.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public abstract class ConfigurationInstance<T> where T : class
    {
        private static T _config;

        /// <summary>
        /// Gets the config.
        /// </summary>
        /// <returns></returns>
        public static T GetConfig()
        {
            if (_config == null)
            {
                _config = ConfigurationReader.GetConfig<T>();

                if (_config == null)
                    throw new ConfigurationErrorsException(
                        string.Format("Configuration section \"{0}\" not found", typeof (T).Name));
            }

            return _config;
        }

        /// <summary>
        /// Refreshes the configuration section, so that next time it is read it is retrieved from the configuration file.
        /// </summary>
        public static void Refresh()
        {
            _config = null;
            ConfigurationReader.RefreshConfig<T>();
        }
    }
}