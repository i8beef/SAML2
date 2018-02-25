﻿using System.Collections.Generic;

namespace SAML2.Config
{
    /// <summary>
    /// SAML2 Configuration Section.
    /// </summary>
    public class Saml2Config
    {
        /// <summary>
        /// The configuration
        /// </summary>
        private static Saml2Config _config;

        private Saml2Config()
        {
            Actions = new List<Action>();
            AllowedAudienceUris = new List<string>();
            CommonDomainCookie = new CommonDomainCookie();
            IdentityProviders = new List<IdentityProvider>();
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
                    _config = new Saml2Config();

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
        public IList<IdentityProvider> IdentityProviders { get; set; }

        /// <summary>
        /// Gets the selection URL to use for choosing identity providers if multiple are available and none are set as default.
        /// </summary>
        public string IdentityProviderSelectionUrl { get; set; }

        /// <summary>
        /// Gets or sets the metadata location.
        /// </summary>
        public string IdentityProviderMetadataLocation { get; set; }

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
    }
}
