using System.Collections.Generic;
using System.Linq;

namespace SAML2.Config
{
    /// <summary>
    /// ServiceProvider config item.
    /// </summary>
    public class ServiceProviderConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ServiceProviderConfig"/> class.
        /// </summary>
        public ServiceProviderConfig()
        {
            AuthenticationContextComparison = AuthenticationContextComparison.Exact;
            AuthenticationContexts = new List<AuthenticationContext>();
            Endpoints = new List<ServiceProviderEndpoint>();
            NameIdFormats = new List<string>();
        }

        /// <summary>
        /// Gets or sets the id.
        /// </summary>
        /// <value>The id.</value>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the server.
        /// </summary>
        /// <value>The server.</value>
        public string Server { get; set; }

        /// <summary>
        /// Gets or sets the comparison.
        /// </summary>
        public AuthenticationContextComparison AuthenticationContextComparison { get; set; }

        /// <summary>
        /// Gets or sets the authentication contexts.
        /// </summary>
        /// <value>The authentication contexts.</value>
        public IList<AuthenticationContext> AuthenticationContexts { get; set; }

        /// <summary>
        /// Gets or sets the endpoints.
        /// </summary>
        /// <value>The endpoints.</value>
        public IList<ServiceProviderEndpoint> Endpoints { get; set; }

        /// <summary>
        /// Gets the log off endpoint.
        /// </summary>
        public ServiceProviderEndpoint LogoutEndpoint
        {
            get { return Endpoints.FirstOrDefault(x => x.Type == EndpointType.Logout); }
        }

        /// <summary>
        /// Gets the sign on endpoint.
        /// </summary>
        public ServiceProviderEndpoint SignOnEndpoint
        {
            get { return Endpoints.FirstOrDefault(x => x.Type == EndpointType.SignOn); }
        }

        /// <summary>
        /// Gets or sets a value indicating whether to allow creation of new NameIdFormats.
        /// </summary>
        public bool NameIdFormatAllowCreate { get; set; }

        /// <summary>
        /// Gets or sets the name id formats.
        /// </summary>
        /// <value>The name id formats.</value>
        public IList<string> NameIdFormats { get; set; }

        /// <summary>
        /// Gets or sets the signing certificate.
        /// </summary>
        /// <value>The signing certificate.</value>
        public Certificate SigningCertificate { get; set; }
    }
}
