using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SAML2.Bindings.SignatureProviders
{
    internal abstract class SignatureProvider : ISignatureProvider
    {
        public abstract string SignatureUri { get; }

        public abstract string DigestUri { get; }

        public byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var rsa = (RSACryptoServiceProvider)key;

            rsa = ConvertProviderType(rsa);

            return SignDataIntern(rsa, data);
        }

        protected abstract byte[] SignDataIntern(RSACryptoServiceProvider key, byte[] data);

        public bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var rsa = (RSACryptoServiceProvider)key;

            rsa = ConvertProviderType(rsa);

            return VerifySignatureIntern(rsa, data, signature);
        }

        protected abstract bool VerifySignatureIntern(RSACryptoServiceProvider key, byte[] data, byte[] signature);

        public void SignAssertion(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = Sign(doc, id, cert);
            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            XmlNodeList nodes = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            nodes[0].ParentNode.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);
        }

        public void SignMetaData(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = Sign(doc, id, cert);
            doc.DocumentElement.InsertBefore(doc.ImportNode(signedXml.GetXml(), true), doc.DocumentElement.FirstChild);
        }
        private SignedXml Sign(XmlDocument doc, string id, X509Certificate2 cert)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignatureUri;
            signedXml.SigningKey = cert.GetRSAPrivateKey();

            // Retrieve the value of the "ID" attribute on the root assertion element.
            Reference reference = new Reference("#" + id);
            reference.DigestMethod = DigestUri;

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.WholeChain));

            signedXml.ComputeSignature();
            return signedXml;
        }

        private static RSACryptoServiceProvider ConvertProviderType(RSACryptoServiceProvider rsa)
        {
            // ProviderType == 1 is PROV_RSA_FULL provider type that only supports SHA1. Change it to PROV_RSA_AES=24 that supports SHA2 also.
            // https://github.com/Microsoft/referencesource/blob/master/System.IdentityModel/System/IdentityModel/Tokens/X509AsymmetricSecurityKey.cs#L54
            if (rsa != null && rsa.CspKeyContainerInfo.ProviderType == 1)
            {
                //if (Trace.ShouldTrace(TraceEventType.Verbose))
                //{
                //    Trace.TraceData(TraceEventType.Verbose,
                //        "Changed provider type from " + rsa.CspKeyContainerInfo.ProviderType + " to 24");
                //}
                CspParameters csp = new CspParameters();
                csp.ProviderType = 24;
                csp.KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName;
                csp.KeyNumber = (int)rsa.CspKeyContainerInfo.KeyNumber;
                if (rsa.CspKeyContainerInfo.MachineKeyStore)
                    csp.Flags = CspProviderFlags.UseMachineKeyStore;
                csp.Flags |= CspProviderFlags.UseExistingKey;
                rsa = new RSACryptoServiceProvider(csp);
            }
            return rsa;
        }
    }
}