using System.Collections.Generic;
using SAML2.Config;
using SAML2.Exceptions;

namespace SAML2.Validation
{
    /// <summary>
    /// <see cref="Saml2Config"/> validator.
    /// </summary>
    public class Saml2ConfigValidator
    {
        /// <summary>
        /// Identity provider validator.
        /// </summary>
        private readonly IdentityProviderValidator _identityProviderValidator = new IdentityProviderValidator();

        /// <summary>
        /// Service provider config validator.
        /// </summary>
        private readonly ServiceProviderConfigValidator _serviceProviderConfigValidator = new ServiceProviderConfigValidator();

        /// <summary>
        /// Validates the <see cref="Saml2Config"/>.
        /// </summary>
        /// <param name="config">The <see cref="Saml2Config"/> to validate.</param>
        public void ValidateConfig(Saml2Config config)
        {
            ValidateActions(config.Actions);
            ValidateAllowedAudienceUris(config.AllowedAudienceUris);
            ValidateAssertionProfile(config.AssertionProfile);
            ValidateCommonDomainCookie(config.CommonDomainCookie);
            ValidateLogging(config.Logging);
            ValidateMetadata(config.Metadata);
            ValidateState(config.State);

            _serviceProviderConfigValidator.ValidateServiceProviderConfig(config.ServiceProvider);
            ValidateIdentityProviders(config.IdentityProviders);
        }

        /// <summary>
        /// Validates the <see cref="Action"/> list.
        /// </summary>
        /// <param name="actions">The <see cref="Action"/> list.</param>
        private void ValidateActions(IList<Action> actions)
        {
            if (actions == null)
            {
                throw new Saml20ConfigurationException("Configuration Actions cannot be null");
            }
        }

        /// <summary>
        /// Validates the allowed audience uris.
        /// </summary>
        /// <param name="allowedAudienceUris">The list of allowed audience uris.</param>
        private void ValidateAllowedAudienceUris(IList<string> allowedAudienceUris)
        {
            if (allowedAudienceUris == null)
            {
                throw new Saml20ConfigurationException("Configuration AllowedAudienceUris cannot be null");
            }

            if (allowedAudienceUris.Count == 0)
            {
                throw new Saml20ConfigurationException("Configuration AllowedAudienceUris cannot be empty");
            }
        }

        /// <summary>
        /// Validates the <see cref="AssertionProfile"/>.
        /// </summary>
        /// <param name="assertionProfile">The <see cref="AssertionProfile"/>.</param>
        private void ValidateAssertionProfile(AssertionProfile assertionProfile)
        {
            if (assertionProfile == null)
            {
                throw new Saml20ConfigurationException("Configuration AssertionProfile cannot be null");
            }
        }

        /// <summary>
        /// Validates the <see cref="CommonDomainCookie"/>.
        /// </summary>
        /// <param name="commonDomainCookie">The <see cref="CommonDomainCookie"/>.</param>
        private void ValidateCommonDomainCookie(CommonDomainCookie commonDomainCookie)
        {
            if (commonDomainCookie == null)
            {
                throw new Saml20ConfigurationException("Configuration CommonDomainCookie cannot be null");
            }

            if (commonDomainCookie.Enabled && string.IsNullOrEmpty(commonDomainCookie.LocalReaderEndpoint))
            {
                throw new Saml20ConfigurationException("Configuration CommonDomainCookie is enabled, but no LocalReaderEndpoint is supplied");
            }
        }

        /// <summary>
        /// Validates the <see cref="IdentityProviderCollection"/>.
        /// </summary>
        /// <param name="identityProviders">The <see cref="IdentityProviderCollection"/>.</param>
        private void ValidateIdentityProviders(IdentityProviderCollection identityProviders)
        {
            if (identityProviders == null)
            {
                throw new Saml20ConfigurationException("Configuration IdentityProviders cannot be null");
            }

            foreach (var idp in identityProviders)
            {
                _identityProviderValidator.ValidateIdentityProvider(idp);
            }
        }

        /// <summary>
        /// Validates the <see cref="LoggingConfig"/>.
        /// </summary>
        /// <param name="loggingConfig">The <see cref="LoggingConfig"/>.</param>
        private void ValidateLogging(LoggingConfig loggingConfig)
        {
            if (loggingConfig == null)
            {
                throw new Saml20ConfigurationException("Configuration Logging cannot be null");
            }
        }

        /// <summary>
        /// Validates the <see cref="MetadataConfig"/>.
        /// </summary>
        /// <param name="metadataConfig">The <see cref="MetadataConfig"/>.</param>
        private void ValidateMetadata(MetadataConfig metadataConfig)
        {
            if (metadataConfig == null)
            {
                throw new Saml20ConfigurationException("Configuration Metadata cannot be null");
            }

            if (metadataConfig.Contacts == null)
            {
                throw new Saml20ConfigurationException("Configuration Metadata Contacts cannot be null");
            }

            if (metadataConfig.Lifetime == null)
            {
                throw new Saml20ConfigurationException("Configuration Metadata Lifetime cannot be null");
            }

            if (metadataConfig.RequestedAttributes == null)
            {
                throw new Saml20ConfigurationException("Configuration Metadata RequestedAttributes cannot be null");
            }
        }

        /// <summary>
        /// Validates the <see cref="StateConfig"/>.
        /// </summary>
        /// <param name="stateConfig">The <see cref="StateConfig"/>.</param>
        private void ValidateState(StateConfig stateConfig)
        {
            if (stateConfig == null)
            {
                throw new Saml20ConfigurationException("Configuration State cannot be null");
            }

            if (stateConfig.Settings == null)
            {
                throw new Saml20ConfigurationException("Configuration State Settings cannot be null");
            }
        }
    }
}
