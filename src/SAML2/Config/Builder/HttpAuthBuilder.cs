namespace SAML2.Config.Builder
{
    /// <summary>
    /// <see cref="HttpAuth"/> builder.
    /// </summary>
    public class HttpAuthBuilder
    {
        /// <summary>
        /// The client certificate.
        /// </summary>
        private Certificate _clientCertificate;

        /// <summary>
        /// The client credentials.
        /// </summary>
        private HttpAuthCredentials _credentials;

        /// <summary>
        /// Builds a <see cref="IdentityProvider"/> based on the current builder properties.
        /// </summary>
        /// <returns>A <see cref="IdentityProvider"/>.</returns>
        public HttpAuth Build()
        {
            var config = new HttpAuth();

            if (_clientCertificate != null)
            {
                config.ClientCertificate = _clientCertificate;
            }

            if (_credentials != null)
            {
                config.Credentials = _credentials;
            }

            return config;
        }

        /// <summary>
        /// Configures the client certificate.
        /// </summary>
        /// <param name="clientCertificate">The client certificate.</param>
        /// <returns>The <see cref="HttpAuthBuilder"/>.</returns>
        public HttpAuthBuilder WithClientCertificate(Certificate clientCertificate)
        {
            _clientCertificate = clientCertificate;
            return this;
        }

        /// <summary>
        /// Configures the credentials.
        /// </summary>
        /// <param name="credentials">The credentials.</param>
        /// <returns>The <see cref="HttpAuthBuilder"/>.</returns>
        public HttpAuthBuilder WithCredentials(HttpAuthCredentials credentials)
        {
            _credentials = credentials;
            return this;
        }
    }
}
