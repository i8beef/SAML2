using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Xml;
using SAML2;
using SAML2.Schema.Metadata;
using SAML2.Utils;
using NUnit.Framework;

namespace SAML2.Tests.Saml20.Protocol
{
    [TestFixture]
    public class SamlMetadataDocumentTest
    {
        // <summary>
        /// Sign an &lt;EntityDescriptor&gt; metadata element.
        /// </summary>
        [Test]
        [Explicit]
        public void TestSigning_01()
        {
            Saml20MetadataDocument doc = new Saml20MetadataDocument(true);
            
            EntityDescriptor entity = doc.CreateDefaultEntity();
            entity.validUntil = DateTime.Now.AddDays(14);

            Console.WriteLine(doc.ToXml());
            
        }

        [Test]
        public void TestCertificateExtraction_01()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(@"Protocol\MetadataDocs\metadata-ADLER.xml");
            
            Saml20MetadataDocument metadata = new Saml20MetadataDocument(doc);
            List<KeyDescriptor> keys = metadata.Keys;            

            Assert.That(keys[0].use == KeyTypes.signing);
            Assert.That(keys[1].use == KeyTypes.encryption);

            Assert.That(metadata.GetKeys(KeyTypes.signing).Count == 1);
            Assert.That(metadata.GetKeys(KeyTypes.encryption).Count == 1);

            // The two certs in the metadata document happen to be identical, and are also 
            // used for signing the entire document.
            // Extract the certificate and verify the document.

            KeyInfo keyinfo = (KeyInfo) keys[0].KeyInfo;
            Assert.That(XmlSignatureUtils.CheckSignature(doc, keyinfo));
            Assert.AreEqual("ADLER_SAML20_ID", metadata.EntityId);            
        }

        [Test]
        public void TestEndpointExtraction()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(@"Protocol\MetadataDocs\metadata-ADLER.xml");
            
            Saml20MetadataDocument metadata = new Saml20MetadataDocument(doc);
            Assert.AreEqual(2, metadata.SLOEndpoints().Count);
            Assert.AreEqual(2, metadata.SSOEndpoints().Count);
        }
    }
}