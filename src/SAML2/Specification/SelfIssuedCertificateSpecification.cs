using System;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;
using SAML2.Properties;
using Trace=SAML2.Utils.Trace;

namespace SAML2.Specification
{
    /// <summary>
    /// Validates a selfsigned certificate
    /// </summary>
    public class SelfIssuedCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid by this specification.
        /// Always returns true. No online validation attempted.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <returns>
        /// 	<c>true</c>.
        /// </returns>
        public bool IsSatisfiedBy(X509Certificate2 certificate)
        {
            X509ChainPolicy chainPolicy = new X509ChainPolicy();
            chainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            X509CertificateValidator defaultCertificateValidator = X509CertificateValidator.CreateChainTrustValidator(false, chainPolicy);

            try
            {
                defaultCertificateValidator.Validate(certificate);
                return true;
            }
            catch (Exception e)
            {
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
            }

            return false;
        }
    }
}
