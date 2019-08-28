using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SAML2.Bindings.SignatureProviders
{
    /// <summary>
    /// can provide signatures based on bytes or XML
    /// </summary>
    public interface ISignatureProvider
    {
        /// <summary>
        /// Defines the signature algorithm
        /// </summary>
        string SignatureUri { get; }

        /// <summary>
        /// Defines the digest algorithm
        /// </summary>
        string DigestUri { get; }

        /// <summary>
        /// Signs a chunk of bytes. If provider type is 1 it will be converted to 24 in order to support SHA2
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        byte[] SignData(AsymmetricAlgorithm key, byte[] data);

        /// <summary>
        /// Verifies a a chunk of bytes. If provider type is 1 it will be converted to 24 in order to support SHA2
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature);
        
        /// <summary>
        /// Signs a document with an xml signature using the signing certificate given as argument to the method.
        /// </summary>
        /// <param name="doc">The XmlDocument to be signed</param>
        /// <param name="id">The is of the topmost element in the xmldocument</param>
        /// <param name="cert">The certificate used to sign the document</param>
        void SignAssertion(XmlDocument doc, string id, X509Certificate2 cert);

        /// <summary>
        /// Signs metadata with an xml signature using the signing certificate given as argument to the method.
        /// </summary>
        /// <param name="doc">The XmlDocument to be signed</param>
        /// <param name="id">The is of the topmost element in the xmldocument</param>
        /// <param name="cert">The certificate used to sign the document</param>
        void SignMetaData(XmlDocument doc, string id, X509Certificate2 cert);
    }
}