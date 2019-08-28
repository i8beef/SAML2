using System;
using System.Security.Cryptography.Xml;
using SAML2.Config;

namespace SAML2.Bindings.SignatureProviders
{
    /// <summary>
    /// Provides concrete instances of <see cref="ISignatureProvider"/>
    /// </summary>
    public class SignatureProviderFactory
    {
        /// <summary>
        /// returns the validated <see cref="InvalidOperationException"/>
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ShaHashingAlgorithm"></exception>
        public static ShaHashingAlgorithm ValidateShaHashingAlgorithm(string shaHashingAlgorithm)
        {
            ShaHashingAlgorithm val;
            if (Enum.TryParse(shaHashingAlgorithm, out val) && Enum.IsDefined(typeof(ShaHashingAlgorithm), val))
            {
                return val;
            }

            throw new InvalidOperationException($"The value of the configuration element 'ShaHashingAlgorithm' is not valid: '{shaHashingAlgorithm}'. Value must be either SHA1, SHA256 or SHA512");
        }

        /// <summary>
        /// Returns a signature provider based on a hashing algorithm
        /// </summary>
        /// <param name="algorithmUri"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromHashingAlgorithmSignatureUri(string algorithmUri)
        {
            switch (algorithmUri)
            {
                case SignedXml.XmlDsigRSASHA1Url: return CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm.SHA1);
                case SignedXml.XmlDsigRSASHA256Url: return CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm.SHA256);
                case SignedXml.XmlDsigRSASHA512Url: return CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm.SHA512);
                default:
                    throw new InvalidOperationException(
                        $"Unsupported hashing algorithm uri '{algorithmUri}' provided while using RSA signing key");
            }
        }

        /// <summary>
        /// Returns a signature provider based on a hashing algorithm
        /// </summary>
        /// <param name="hashingAlgorithm"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm hashingAlgorithm)
        {
            switch (hashingAlgorithm)
            {
                case ShaHashingAlgorithm.SHA1: return new RsaSha1SignatureProvider();
                case ShaHashingAlgorithm.SHA256: return new RsaSha256SignatureProvider();
                case ShaHashingAlgorithm.SHA512: return new RsaSha512SignatureProvider();
                default:
                    throw new InvalidOperationException(
                        $"Unsupported hashing algorithm '{hashingAlgorithm}' provideded while using RSA signing key");
            }
        }
    }
}