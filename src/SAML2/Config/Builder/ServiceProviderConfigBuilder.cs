using System.Collections.Generic;

namespace SAML2.Config.Builder
{
    /// <summary>
    /// <see cref="ServiceProviderConfig"/> builder.
    /// </summary>
    public class ServiceProviderConfigBuilder
    {
        /// <summary>
        /// The authentication contexts.
        /// </summary>
        private IList<AuthenticationContext> _authenticationContexts;

        /// <summary>
        /// The authentication context comparison.
        /// </summary>
        private AuthenticationContextComparison _authenticationContextComparison;

        /// <summary>
        /// The endpoints.
        /// </summary>
        private IList<ServiceProviderEndpoint> _endpoints;

        /// <summary>
        /// The id.
        /// </summary>
        private string _id;

        /// <summary>
        /// The name id formats.
        /// </summary>
        private IList<string> _nameIdFormats;

        /// <summary>
        /// Whether creating name id formats is allowed.
        /// </summary>
        private bool _nameIdFormatAllowCreate;

        /// <summary>
        /// The server.
        /// </summary>
        private string _server;

        /// <summary>
        /// The signing certificate.
        /// </summary>
        private Certificate _signingCertificate;

        /// <summary>
        /// Initializes a new instance of the <see cref="ServiceProviderConfigBuilder"/> class.
        /// </summary>
        public ServiceProviderConfigBuilder()
        {
            _authenticationContextComparison = AuthenticationContextComparison.Exact;
            _authenticationContexts = new List<AuthenticationContext>();
            _endpoints = new List<ServiceProviderEndpoint>();
            _nameIdFormats = new List<string>();
        }

        /// <summary>
        /// Builds a <see cref="ServiceProviderConfig"/> based on the current builder properties.
        /// </summary>
        /// <returns>A <see cref="ServiceProviderConfig"/>.</returns>
        public ServiceProviderConfig Build()
        {
            var config = new ServiceProviderConfig();

            config.AuthenticationContextComparison = _authenticationContextComparison;
            config.Id = _id;
            config.NameIdFormatAllowCreate = _nameIdFormatAllowCreate;
            config.Server = _server;

            if (_signingCertificate != null)
            {
                config.SigningCertificate = _signingCertificate;
            }

            foreach (var authenticationContext in _authenticationContexts)
            {
                config.AuthenticationContexts.Add(authenticationContext);
            }

            foreach (var endpoint in _endpoints)
            {
                config.Endpoints.Add(endpoint);
            }

            foreach (var nameIdFormat in _nameIdFormats)
            {
                config.NameIdFormats.Add(nameIdFormat);
            }

            return config;
        }

        /// <summary>
        /// Adds an authentication context to the config.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="referenceType">The reference type.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder AddAuthenticationContext(string context, string referenceType)
        {
            _authenticationContexts.Add(new AuthenticationContext { Context = context, ReferenceType = referenceType });
            return this;
        }

        /// <summary>
        /// Adds an <see cref="ServiceProviderEndpoint"/> to the config.
        /// </summary>
        /// <param name="endpoint">The <see cref="ServiceProviderEndpoint"/> to add.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder AddEndpoint(ServiceProviderEndpoint endpoint)
        {
            _endpoints.Add(endpoint);
            return this;
        }

        /// <summary>
        /// Adds a NameIdFormat to the config.
        /// </summary>
        /// <param name="nameIdFormat">The NameIdFormat string.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder AddNameIdFormat(string nameIdFormat)
        {
            _nameIdFormats.Add(nameIdFormat);
            return this;
        }

        /// <summary>
        /// Configures whether to allow creation of new NameIdFormats.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder AllowNameIdFormatCreate(bool value)
        {
            _nameIdFormatAllowCreate = value;
            return this;
        }

        /// <summary>
        /// Configures the <see cref="AuthenticationContextComparison"/>.
        /// </summary>
        /// <param name="comparison">The <see cref="AuthenticationContextComparison"/>.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder WithAuthenticationContextComparison(AuthenticationContextComparison comparison)
        {
            _authenticationContextComparison = comparison;
            return this;
        }

        /// <summary>
        /// Configures the service provider id.
        /// </summary>
        /// <param name="id">The service provider id.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder WithId(string id)
        {
            _id = id;
            return this;
        }

        /// <summary>
        /// Configures the service provider server.
        /// </summary>
        /// <param name="server">The server.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder WithServer(string server)
        {
            _server = server;
            return this;
        }

        /// <summary>
        /// Configures the signing certificate.
        /// </summary>
        /// <param name="certificate">The signing certificate.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public ServiceProviderConfigBuilder WithSigningCertificate(Certificate certificate)
        {
            _signingCertificate = certificate;
            return this;
        }
    }
}
