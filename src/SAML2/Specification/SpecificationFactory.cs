using System;
using System.Collections.Generic;
using System.Diagnostics;
using SAML2.config;
using Trace=SAML2.Utils.Trace;

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
        public static List<ICertificateSpecification> GetCertificateSpecifications(IDPEndPoint endpoint)
        {
            List<ICertificateSpecification> specs = new List<ICertificateSpecification>();

            if(endpoint.CertificateValidation != null && endpoint.CertificateValidation.CertificateValidations != null &&
                endpoint.CertificateValidation.CertificateValidations.Count > 0)
            {
                foreach(CertificateValidationElement elem in endpoint.CertificateValidation.CertificateValidations)
                {
                    try
                    {
                        ICertificateSpecification val = (ICertificateSpecification) Activator.CreateInstance(Type.GetType(elem.type));
                        specs.Add(val);
                    }catch(Exception e)
                    {
                        Trace.TraceData(TraceEventType.Error, e.ToString());
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
