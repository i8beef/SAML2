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
            if (string.IsNullOrEmpty(config.Id))
            {
                throw new Saml20ConfigurationException("Configuration ServiceProvider Id cannot be null or empty");
            }
        }
    }
}
