using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SAML2.Properties;
using Trace=SAML2.Utils.Trace;

namespace SAML2.Specification
{
    /// <summary>
    /// Checks if a certificate is within its validity period
    /// Performs an online revocation check if the certificate contains a CRL url (oid: 2.5.29.31)
    /// </summary>
    public class DefaultCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid according to the RFC3280 specification.
        /// 
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <returns>
        /// 	<c>true</c> if valid; otherwise, <c>false</c>.
        /// </returns>
        public bool IsSatisfiedBy(X509Certificate2 certificate)
        {
            bool useMachineContext = false;
            X509ChainPolicy chainPolicy = new X509ChainPolicy();
            chainPolicy.RevocationMode = X509RevocationMode.Online;
            X509CertificateValidator defaultCertificateValidator = X509CertificateValidator.CreateChainTrustValidator(useMachineContext, chainPolicy);

            try
            {
                defaultCertificateValidator.Validate(certificate);
                return true;
            }catch(Exception e)
            {
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
            }

            return false;
        }
    }
}
