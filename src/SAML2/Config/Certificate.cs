using System.Security.Cryptography.X509Certificates;

namespace SAML2.Config
{
    /// <summary>
    /// Certificate config.
    /// </summary>
    public class Certificate
    {
        /// <summary>
        /// Gets or sets the find value.
        /// </summary>
        /// <value>The find value.</value>
        public string FindValue { get; set; }

        /// <summary>
        /// Gets or sets the store location.
        /// </summary>
        /// <value>The store location.</value>
        public StoreLocation StoreLocation { get; set; }

        /// <summary>
        /// Gets or sets the name of the store.
        /// </summary>
        /// <value>The name of the store.</value>
        public StoreName StoreName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to only find valid certificates.
        /// </summary>
        /// <value><c>true</c> if only valid certificates should be considered; otherwise, <c>false</c>.</value>
        public bool ValidOnly { get; set; }

        /// <summary>
        /// Gets or sets the X509FindType.
        /// </summary>
        /// <value>The X509FindType.</value>
        public X509FindType X509FindType { get; set; }

        /// <summary>
        /// Opens the certificate from its store.
        /// </summary>
        /// <returns>The <see cref="X509Certificate2"/>.</returns>
        public X509Certificate2 GetCertificate()
        {
            var store = new X509Store(StoreName, StoreLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType, FindValue, ValidOnly);
                if (found.Count == 0)
                {
                    throw new Saml20Exception(string.Format(ErrorMessages.CertificateNotFound, FindValue));
                }

                if (found.Count > 1)
                {
                    throw new Saml20Exception(string.Format(ErrorMessages.CertificateNotUnique, FindValue));
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
