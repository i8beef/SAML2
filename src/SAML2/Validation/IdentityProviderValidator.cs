using SAML2.Config;
using SAML2.Exceptions;

namespace SAML2.Validation
{
    /// <summary>
    /// <see cref="IdentityProvider"/> validator.
    /// </summary>
    public class IdentityProviderValidator
    {
        /// <summary>
        /// Validates the <see cref="IdentityProvider"/>.
        /// </summary>
        /// <param name="identityProvider">The <see cref="IdentityProvider"/> to validate.</param>
        public void ValidateIdentityProvider(IdentityProvider identityProvider)
        {
            if (identityProvider.CertificateValidations == null)
            {
                throw new Saml20ConfigurationException("Configuration IdentityProvider CertificateValidations cannot be null");
            }

            if (identityProvider.CertificateValidations == null)
            {
                throw new Saml20ConfigurationException("Configuration IdentityProvider CertificateValidations cannot be null");
            }

            if (identityProvider.CommonDomainCookie == null)
            {
                throw new Saml20ConfigurationException("Configuration IdentityProvider CommonDomainCookie cannot be null");
            }

            if (identityProvider.Endpoints == null)
            {
                throw new Saml20ConfigurationException("Configuration IdentityProvider Endpoints cannot be null");
            }

            if (string.IsNullOrEmpty(identityProvider.Id))
            {
                throw new Saml20ConfigurationException("Configuration IdentityProvider Id cannot be null or empty");
            }

            if (identityProvider.ArtifactResolution != null)
            {
                if (identityProvider.ArtifactResolution.ClientCertificate == null && identityProvider.ArtifactResolution.Credentials == null)
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider ArtifactResolution must specify one of ClientCertificate or Credentials when present");
                }

                if (identityProvider.ArtifactResolution.ClientCertificate != null && identityProvider.ArtifactResolution.Credentials != null)
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider ArtifactResolution must specify only one of ClientCertificate or Credentials when present");
                }

                if (identityProvider.ArtifactResolution.ClientCertificate != null && string.IsNullOrEmpty(identityProvider.ArtifactResolution.ClientCertificate.FindValue))
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider ArtifactResolution Certificate FindValue cannot be null or empty");
                }
            }

            if (identityProvider.AttributeQuery != null)
            {
                if (identityProvider.AttributeQuery.ClientCertificate == null && identityProvider.AttributeQuery.Credentials == null)
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider AttributeQuery must specify one of ClientCertificate or Credentials when present");
                }

                if (identityProvider.AttributeQuery.ClientCertificate != null && identityProvider.AttributeQuery.Credentials != null)
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider AttributeQuery must specify only one of ClientCertificate or Credentials when present");
                }

                if (identityProvider.AttributeQuery.ClientCertificate != null && string.IsNullOrEmpty(identityProvider.AttributeQuery.ClientCertificate.FindValue))
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider AttributeQuery Certificate FindValue cannot be null or empty");
                }
            }

            foreach (var endpoint in identityProvider.Endpoints)
            {
                if (string.IsNullOrEmpty(endpoint.Url))
                {
                    throw new Saml20ConfigurationException("Configuration IdentityProvider Endpoint Url cannot be null or empty");
                }
            }

            if (identityProvider.PersistentPseudonym != null && string.IsNullOrEmpty(identityProvider.PersistentPseudonym.Mapper))
            {
                throw new Saml20ConfigurationException("Configuration IdentityProvider PersistentPseudonym must specify Mapper when present");
            }
        }
    }
}
