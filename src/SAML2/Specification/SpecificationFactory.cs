using System;
using System.Collections.Generic;
using System.Diagnostics;
using SAML2.Config;

namespace SAML2.Specification
{
    ///<summary>
    /// 
    ///</summary>
    public class SpecificationFactory
    {
        /// <summary>
        /// Gets the certificate specifications.
        /// </summary>
        /// <param name="endpoint">The endpoint.</param>
        /// <returns>A list of certificate validation specifications for this endpoint</returns>
        public static List<ICertificateSpecification> GetCertificateSpecifications(IdentityProviderElement endpoint)
        {
            List<ICertificateSpecification> specs = new List<ICertificateSpecification>();

            if(endpoint.CertificateValidations != null && endpoint.CertificateValidations.Count > 0)
            {
                foreach(CertificateValidationElement elem in endpoint.CertificateValidations)
                {
                    try
                    {
                        ICertificateSpecification val = (ICertificateSpecification) Activator.CreateInstance(Type.GetType(elem.Type));
                        specs.Add(val);
                    }catch(Exception e)
                    {
                        Logging.LoggerProvider.LoggerFor(typeof(SpecificationFactory)).Error(e.Message, e);
                    }
                }
            }

            if(specs.Count == 0)
            {
                //Add default specification
                specs.Add(new DefaultCertificateSpecification());
            }

            return specs;
        }
    }
    
}
