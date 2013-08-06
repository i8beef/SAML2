using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Logging configuration element.
    /// </summary>
    public class LoggingElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the logging factory.
        /// </summary>
        [ConfigurationProperty("loggingFactory")]
        public string LoggingFactory
        {
            get { return (string) base["loggingFactory"];  }
        }

        #endregion
    }
}
