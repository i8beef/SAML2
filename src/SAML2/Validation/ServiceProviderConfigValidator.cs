using SAML2.Config;
using SAML2.Exceptions;

namespace SAML2.Validation
{
    /// <summary>
    /// <see cref="ServiceProviderConfig"/> validator.
    /// </summary>
    public class ServiceProviderConfigValidator
    {
        /// <summary>
        /// Validates the <see cref="ServiceProviderConfig"/>.
        /// </summary>
        /// <param name="config">The <see cref="ServiceProviderConfig"/>.</param>
        public void ValidateServiceProviderConfig(ServiceProviderConfig config)
        {
            if (config.AuthenticationContexts == null)
            {
                throw new Saml20ConfigurationException("Configuration ServiceProvider AuthenticationContexts cannot be null");
            }

            if (config.Endpoints == null)
            {
                throw new Saml20ConfigurationException("Configuration ServiceProvider Endpoints cannot be null");
            }

            foreach (var endpoint in config.Endpoints)
            {
                if (string.IsNullOrEmpty(endpoint.LocalPath))
                {
                    throw new Saml20ConfigurationException("Configuration ServiceProvider Endpoint LocalPath cannot be null or empty");
                }

                if (string.IsNullOrEmpty(endpoint.RedirectUrl))
                {
                    throw new Saml20ConfigurationException("Configuration ServiceProvider Endpoint RedirectUrl cannot be null or empty");
                }
            }

            if (string.IsNullOrEmpty(config.Id))
            {
                throw new Saml20ConfigurationException("Configuration ServiceProvider Id cannot be null or empty");
            }

            if (config.NameIdFormats == null)
            {
                throw new Saml20ConfigurationException("Configuration ServiceProvider NameIdFormats cannot be null");
            }

            if (string.IsNullOrEmpty(config.Server))
            {
                throw new Saml20ConfigurationException("Configuration ServiceProvider Server cannot be null or empty");
            }

            if (config.SigningCertificate != null)
            {
                if (string.IsNullOrEmpty(config.SigningCertificate.FindValue))
                {
                    throw new Saml20ConfigurationException("Configuration ServiceProvider SigningCertificate FindValue cannot be null or empty");
                }
            }
        }
    }
}
