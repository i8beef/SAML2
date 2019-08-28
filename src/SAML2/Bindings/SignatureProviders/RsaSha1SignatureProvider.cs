using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace SAML2.Bindings.SignatureProviders
{
    internal class RsaSha1SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA1Url;
        public override string DigestUri => SignedXml.XmlDsigSHA1Url;
        protected override byte[] SignDataIntern(RSACryptoServiceProvider key, byte[] data)
        {
            return key.SignData(data, new SHA1CryptoServiceProvider());
        }

        protected override bool VerifySignatureIntern(RSACryptoServiceProvider key, byte[] data, byte[] signature)
        {
            var hash = new SHA1Managed().ComputeHash(data);
            return ((RSACryptoServiceProvider) key).VerifyHash(hash, "SHA1", signature);
        }
    }
}