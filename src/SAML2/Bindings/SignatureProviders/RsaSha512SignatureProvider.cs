using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace SAML2.Bindings.SignatureProviders
{
    internal class RsaSha512SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA512Url;
        public override string DigestUri => SignedXml.XmlDsigSHA512Url;
        protected override byte[] SignDataIntern(RSACryptoServiceProvider key, byte[] data)
        {
            return key.SignData(data, new SHA512CryptoServiceProvider());
        }

        protected override bool VerifySignatureIntern(RSACryptoServiceProvider key, byte[] data, byte[] signature)
        {
            var hash = new SHA512Managed().ComputeHash(data);
            return ((RSACryptoServiceProvider)key).VerifyHash(hash, "SHA512", signature);
        }
    }
}