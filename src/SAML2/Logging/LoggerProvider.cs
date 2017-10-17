﻿using System;
using SAML2.Config;

namespace SAML2.Logging
{
    /// <summary>
    /// Logger provider.
    /// </summary>
    public class LoggerProvider
    {
        /// <summary>
        /// Logger provider static instance.
        /// </summary>
        private static LoggerProvider _instance;

        /// <summary>
        /// The logger factory.
        /// </summary>
        private readonly ILoggerFactory _loggerFactory;

        /// <summary>
        /// Initializes static members of the <see cref="LoggerProvider"/> class.
        /// </summary>
        static LoggerProvider()
        {
            var loggerClass = Saml2Config.GetConfigElement().Logging.LoggingFactory;
            var loggerFactory = string.IsNullOrEmpty(loggerClass) ? new NoLoggingLoggerFactory() : GetLoggerFactory(loggerClass);
            SetLoggerFactory(loggerFactory);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LoggerProvider"/> class.
        /// </summary>
        /// <param name="loggerFactory">The logger factory.</param>
        private LoggerProvider(ILoggerFactory loggerFactory)
        {
            _loggerFactory = loggerFactory;
        }

        /// <summary>
        /// Gets a logger for the specified key.
        /// </summary>
        /// <param name="keyName">Name of the key.</param>
        /// <returns>An instance of <see cref="IInternalLogger"/>.</returns>
        public static IInternalLogger LoggerFor(string keyName)
        {
            return _instance._loggerFactory.LoggerFor(keyName);
        }

        /// <summary>
        /// Gets a logger for the specified type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns>An instance of <see cref="IInternalLogger"/>.</returns>
        public static IInternalLogger LoggerFor(Type type)
        {
            return _instance._loggerFactory.LoggerFor(type);
        }

        /// <summary>
        /// Sets the logger factory.
        /// </summary>
        /// <param name="loggerFactory">The logger factory.</param>
        public static void SetLoggerFactory(ILoggerFactory loggerFactory)
        {
            _instance = new LoggerProvider(loggerFactory);
        }
        
        /// <summary>
        /// Gets the logger factory.
        /// </summary>
        /// <param name="saml2LoggerClass">The SAML2 logger class.</param>
        /// <returns>The implementation of <see cref="ILoggerFactory"/>.</returns>
        private static ILoggerFactory GetLoggerFactory(string saml2LoggerClass)
        {
            ILoggerFactory loggerFactory;
            var loggerFactoryType = Type.GetType(saml2LoggerClass);
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
    }
}
