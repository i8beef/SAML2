using System;
using System.Collections.Generic;

namespace SAML2.Config.Builder
{
    /// <summary>
    /// <see cref="Saml2Config"/> builder.
    /// </summary>
    public class Saml2ConfigBuilder
    {
        /// <summary>
        /// The <see cref="Action"/> list.
        /// </summary>
        private IList<Action> _actions;

        /// <summary>
        /// The allowed audiences.
        /// </summary>
        private IList<string> _allowedAudienceUris;

        /// <summary>
        /// The assertion validator.
        /// </summary>
        private string _assertionValidator;

        /// <summary>
        /// The common domain cookie local reader endpoint.
        /// </summary>
        private string _commonDomainCookieLocalReaderEndpoint;

        /// <summary>
        /// The identity providers.
        /// </summary>
        private IList<IdentityProvider> _identityProviders;

        /// <summary>
        /// The identity provider selection url.
        /// </summary>
        private string _identityProviderSelectionUrl;

        /// <summary>
        /// The identity provider metadata location.
        /// </summary>
        private string _identityProviderMetadataLocation;

        /// <summary>
        /// The logging factory type.
        /// </summary>
        private string _loggingFactory;

        /// <summary>
        /// The metadata config.
        /// </summary>
        private MetadataConfig _metadataConfig;

        /// <summary>
        /// The service provider config.
        /// </summary>
        private ServiceProviderConfig _serviceProviderConfig;

        /// <summary>
        /// The state service factory type.
        /// </summary>
        private string _stateServiceFactory;

        /// <summary>
        /// The state settings.
        /// </summary>
        private IDictionary<string, string> _stateSettings;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2ConfigBuilder"/> class.
        /// </summary>
        public Saml2ConfigBuilder()
        {
            _actions = new List<Action>();
            _allowedAudienceUris = new List<string>();
            _identityProviders = new List<IdentityProvider>();
            _stateSettings = new Dictionary<string, string>();
        }

        /// <summary>
        /// Builds a <see cref="Saml2Config"/> based on the current builder properties.
        /// </summary>
        /// <returns>A <see cref="Saml2Config"/>.</returns>
        public Saml2Config Build()
        {
            var config = new Saml2Config();

            config.AssertionProfile.AssertionValidator = _assertionValidator;
            config.CommonDomainCookie.Enabled = !string.IsNullOrEmpty(_commonDomainCookieLocalReaderEndpoint);
            config.CommonDomainCookie.LocalReaderEndpoint = _commonDomainCookieLocalReaderEndpoint;
            config.IdentityProviderSelectionUrl = _identityProviderSelectionUrl;
            config.IdentityProviders.MetadataLocation = _identityProviderMetadataLocation;
            config.State.StateServiceFactory = _stateServiceFactory;
            config.Logging.LoggingFactory = _loggingFactory;

            if (_metadataConfig != null)
            {
                config.Metadata = _metadataConfig;
            }

            if (_serviceProviderConfig != null)
            {
                config.ServiceProvider = _serviceProviderConfig;
            }

            foreach (var action in _actions)
            {
                config.Actions.Add(action);
            }

            foreach (var allowedAudienceUri in _allowedAudienceUris)
            {
                config.AllowedAudienceUris.Add(allowedAudienceUri);
            }

            foreach (var identityProvider in _identityProviders)
            {
                config.IdentityProviders.Add(identityProvider);
            }

            foreach (var key in _stateSettings.Keys)
            {
                config.State.Settings.Add(key, _stateSettings[key]);
            }

            return config;
        }

        /// <summary>
        /// Adds a <see cref="Action"/> to the config.
        /// </summary>
        /// <param name="action">The <see cref="Action"/> to add.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder AddAction(Action action)
        {
            _actions.Add(action);
            return this;
        }

        /// <summary>
        /// Adds an allowed audience url to the config.
        /// </summary>
        /// <param name="allowedAudienceUri">The allowed audience url to add.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder AddAllowedAudienceUri(string allowedAudienceUri)
        {
            _allowedAudienceUris.Add(allowedAudienceUri);
            return this;
        }

        /// <summary>
        /// Adds an <see cref="IdentityProvider"/> to the config.
        /// </summary>
        /// <param name="predicate">The identity provider configuration.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder AddIdentityProvider(Action<IdentityProviderBuilder> predicate)
        {
            var builder = new IdentityProviderBuilder();
            predicate(builder);
            _identityProviders.Add(builder.Build());
            return this;
        }

        /// <summary>
        /// Adds a state configuration setting to the config.
        /// </summary>
        /// <param name="key">The key to add.</param>
        /// <param name="value">The value to add.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder AddStateSetting(string key, string value)
        {
            _stateSettings.Add(key, value);
            return this;
        }

        /// <summary>
        /// Configures an assertion validator.
        /// </summary>
        /// <param name="assertionValidator">The assertion validator type to configure.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithAssertionValidator(string assertionValidator)
        {
            _assertionValidator = assertionValidator;
            return this;
        }

        /// <summary>
        /// Configures a common domain cookie endpoint.
        /// </summary>
        /// <param name="endpoint">The common domain cookie endpoint.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithCommonDomainCookie(string endpoint)
        {
            _commonDomainCookieLocalReaderEndpoint = endpoint;
            return this;
        }

        /// <summary>
        /// Configures the identity provider metadata path.
        /// </summary>
        /// <param name="path">The identity provider metadata path.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithIdentityProviderMetadataLocation(string path)
        {
            _identityProviderMetadataLocation = path;
            return this;
        }

        /// <summary>
        /// Configures the identity provider selection url.
        /// </summary>
        /// <param name="url">The identity provider selection url</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithIdentityProviderSelectionUrl(string url)
        {
            _identityProviderSelectionUrl = url;
            return this;
        }

        /// <summary>
        /// Configures the logging factory type.
        /// </summary>
        /// <param name="loggingFactory">The logging factory type.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithLoggingFactory(string loggingFactory)
        {
            _loggingFactory = loggingFactory;
            return this;
        }

        /// <summary>
        /// Configures the metadata.
        /// </summary>
        /// <param name="predicate">The metadata configuration.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithMetadataConfig(Action<MetadataConfigBuilder> predicate)
        {
            var builder = new MetadataConfigBuilder();
            predicate(builder);
            _metadataConfig = builder.Build();
            return this;
        }

        /// <summary>
        /// Configures the service provider.
        /// </summary>
        /// <param name="predicate">The service provider configuration.</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithServiceProvider(Action<ServiceProviderConfigBuilder> predicate)
        {
            var builder = new ServiceProviderConfigBuilder();
            predicate(builder);
            _serviceProviderConfig = builder.Build();
            return this;
        }

        /// <summary>
        /// Configures the state factory type.
        /// </summary>
        /// <param name="stateServiceFactory">The state factory type</param>
        /// <returns>The <see cref="Saml2ConfigBuilder"/>.</returns>
        public Saml2ConfigBuilder WithStateFactory(string stateServiceFactory)
        {
            _stateServiceFactory = stateServiceFactory;
            return this;
        }
    }
}
