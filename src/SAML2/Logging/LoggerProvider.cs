using System;
using SAML2.Config;

namespace SAML2.Logging
{
    /// <summary>
    /// Logger provider.
    /// </summary>
    public class LoggerProvider
    {
        /// <summary>
        /// The logger factory.
        /// </summary>
        private readonly ILoggerFactory loggerFactory;

        /// <summary>
        /// Logger provider static instance.
        /// </summary>
        private static LoggerProvider instance;

        /// <summary>
        /// Initializes the <see cref="LoggerProvider"/> class.
        /// </summary>
        static LoggerProvider()
        {
            string loggerClass = SAML20FederationConfig.GetConfig().Logging.LoggingFactory;
            ILoggerFactory loggerFactory = string.IsNullOrEmpty(loggerClass) ? new NoLoggingLoggerFactory() : GetLoggerFactory(loggerClass);
            SetLoggersFactory(loggerFactory);
        }

        /// <summary>
        /// Gets the logger factory.
        /// </summary>
        /// <param name="saml2LoggerClass">The SAML2 logger class.</param>
        /// <returns>The implementation of <see cref="ILoggerFactory"/>.</returns>
        private static ILoggerFactory GetLoggerFactory(string saml2LoggerClass)
        {
            ILoggerFactory loggerFactory;
            var loggerFactoryType = System.Type.GetType(saml2LoggerClass);
            try
            {
                loggerFactory = (ILoggerFactory)Activator.CreateInstance(loggerFactoryType);
            }
            catch (MissingMethodException ex)
            {
                throw new ApplicationException("Public constructor was not found for " + loggerFactoryType, ex);
            }
            catch (InvalidCastException ex)
            {
                throw new ApplicationException(loggerFactoryType + "Type does not implement " + typeof(ILoggerFactory), ex);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Unable to instantiate: " + loggerFactoryType, ex);
            }
            return loggerFactory;
        }

        /// <summary>
        /// Sets the loggers factory.
        /// </summary>
        /// <param name="loggerFactory">The logger factory.</param>
        public static void SetLoggersFactory(ILoggerFactory loggerFactory)
        {
            instance = new LoggerProvider(loggerFactory);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LoggerProvider"/> class.
        /// </summary>
        /// <param name="loggerFactory">The logger factory.</param>
        private LoggerProvider(ILoggerFactory loggerFactory)
        {
            this.loggerFactory = loggerFactory;
        }

        /// <summary>
        /// Loggers for.
        /// </summary>
        /// <param name="keyName">Name of the key.</param>
        /// <returns></returns>
        public static IInternalLogger LoggerFor(string keyName)
        {
            return instance.loggerFactory.LoggerFor(keyName);
        }

        /// <summary>
        /// Loggers for.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        public static IInternalLogger LoggerFor(System.Type type)
        {
            return instance.loggerFactory.LoggerFor(type);
        }
    }
}
