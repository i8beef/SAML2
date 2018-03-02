using System;
using System.Collections.Generic;
using SAML2.Config.Builder;
using SAML2.Exceptions;

namespace SAML2.Config
{
    /// <summary>
    /// SAML2 Configuration.
    /// </summary>
    public class Saml2Config
    {
        /// <summary>
        /// The configuration
        /// </summary>
        private static Saml2Config _config;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2Config"/> class.
        /// </summary>
        public Saml2Config()
        {
            Actions = new List<Action>();
            AllowedAudienceUris = new List<string>();
            AssertionProfile = new AssertionProfile();
            CommonDomainCookie = new CommonDomainCookie();
            Logging = new LoggingConfig();
            Metadata = new MetadataConfig();
            IdentityProviders = new IdentityProviderCollection();
            ServiceProvider = new ServiceProviderConfig();
            State = new StateConfig();
        }

        /// <summary>
        /// Gets the config.
        /// </summary>
        /// <returns>The <see cref="Saml2Config"/> config.</returns>
        public static Saml2Config Current
        {
            get
            {
                if (_config == null)
                {
                    InitFromConfigFile();
                }

                if (_config == null)
                {
                    throw new Saml20Exception(ErrorMessages.ConfigNotInitialized);
                }

                return _config;
            }
        }

        /// <summary>
        /// Gets or sets the actions to perform on successful processing.
        /// </summary>
        /// <value>The actions.</value>
        public IList<Action> Actions { get; set; }

        /// <summary>
        /// Gets or sets the allowed audience uris.
        /// </summary>
        /// <value>The allowed audience uris.</value>
        public IList<string> AllowedAudienceUris { get; set; }

        /// <summary>
        /// Gets or sets the assertion profile.
        /// </summary>
        /// <value>The assertion profile configuration.</value>
        public AssertionProfile AssertionProfile { get; set; }

        /// <summary>
        /// Gets or sets the common domain cookie configuration.
        /// </summary>
        /// <value>The common domain cookie configuration.</value>
        public CommonDomainCookie CommonDomainCookie { get; set; }

        /// <summary>
        /// Gets or sets the identity providers.
        /// </summary>
        /// <value>The identity providers.</value>
        public IdentityProviderCollection IdentityProviders { get; set; }

        /// <summary>
        /// Gets or sets the selection URL to use for choosing identity providers if multiple are available and none are set as default.
        /// </summary>
        public string IdentityProviderSelectionUrl { get; set; }

        /// <summary>
        /// Gets or sets the logging configuration.
        /// </summary>
        /// <value>The logging configuration.</value>
        public LoggingConfig Logging { get; set; }

        /// <summary>
        /// Gets or sets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        public MetadataConfig Metadata { get; set; }

        /// <summary>
        /// Gets or sets the service provider.
        /// </summary>
        /// <value>The service provider.</value>
        public ServiceProviderConfig ServiceProvider { get; set; }

        /// <summary>
        /// Gets or sets the state service configuration.
        /// </summary>
        /// <value>The state service configuration.</value>
        public StateConfig State { get; set; }

        /// <summary>
        /// Reads configuration from app.config or web.config.
        /// </summary>
        public static void InitFromConfigFile()
        {
            var config = Saml2Section.GetConfig();
            config.Validate();

            _config = config;
            _config.IdentityProviders.Refresh();
        }

        /// <summary>
        /// Configures the library instance with the specified configuration.
        /// </summary>
        /// <param name="config">Configuration definition.</param>
        public static void Init(Saml2Config config)
        {
            config.Validate();

            _config = config;
            _config.IdentityProviders.Refresh();
        }

        /// <summary>
        /// Configures the library instance with an exposed <see cref="Saml2ConfigBuilder"/>.
        /// </summary>
        /// <param name="predicate">The configuration.</param>
        public static void Init(Action<Saml2ConfigBuilder> predicate)
        {
            var builder = new Saml2ConfigBuilder();
            predicate(builder);
            var config = builder.Build();
            config.Validate();

            _config = config;
            _config.IdentityProviders.Refresh();
        }

        /// <summary>
        /// Validates this <see cref="Saml2Config"/> instance.
        /// </summary>
        public void Validate()
        {
            throw new Saml20ConfigurationException();
        }
    }
}
