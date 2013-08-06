using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using Saml2.Properties;

namespace SAML2.Config
{
    /// <summary>
    /// Signing Certificate configuration element.
    /// </summary>
    public class SigningCertificateElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets the find value.
        /// </summary>
        [ConfigurationProperty("findValue", IsRequired = true)]
        public string FindValue
        {
            get { return (string) base["findValue"]; }
        }

        /// <summary>
        /// Gets the store location.
        /// </summary>
        [ConfigurationProperty("storeLocation", IsRequired = true)]
        public StoreLocation StoreLocation
        {
            get { return (StoreLocation)base["storeLocation"]; }
        }

        /// <summary>
        /// Gets the name of the store.
        /// </summary>
        [ConfigurationProperty("storeName", IsRequired = true)]
        public StoreName StoreName
        {
            get { return (StoreName)base["storeName"]; }
        }

        /// <summary>
        /// Gets a value indicating whether to only find valid certificates.
        /// </summary>
        [ConfigurationProperty("validOnly")]
        public bool ValidOnly
        {
            get { return (bool) base["idvalidOnly"]; }
        }

        /// <summary>
        /// Gets the type of the X509 find.
        /// </summary>
        [ConfigurationProperty("x509FindType", IsRequired = true)]
        public X509FindType X509FindType
        {
            get { return (X509FindType)base["x509FindType"]; }
        }

        #endregion

        /// <summary>
        /// Opens the certificate from its store.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 GetCertificate()
        {
            var store = new X509Store(StoreName, StoreLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType, FindValue, ValidOnly);
                if (found.Count == 0)
                {
                    throw new ConfigurationErrorsException(Resources.CertificateNotFoundFormat(FindValue));
                }

                if (found.Count > 1)
                {
                    throw new ConfigurationErrorsException(Resources.CertificateMoreThanOneFoundFormat(FindValue));
                }

                return found[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}
