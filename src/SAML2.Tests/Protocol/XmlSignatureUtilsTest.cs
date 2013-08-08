using System;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using SAML2.Utils;
using NUnit.Framework;

namespace SAML2.Tests.Saml20.Protocol
{
    /// <summary>
    /// Tests the Safewhere.Tokens.Utils.XmlSignatureUtils class.
    /// </summary>
    [TestFixture]
    public class XmlSignatureUtilsTest
    {
        /// <summary>
        /// Loads a document without a signature.
        /// </summary>
        [Test]
        public void DetectSignature_01()
        {
            Assert.IsFalse((XmlSignatureUtils.IsSigned(LoadDocument(@"Assertions\EncryptedAssertion_01"))));
            Assert.IsTrue(((XmlSignatureUtils.IsSigned(LoadDocument(@"Assertions\Saml2Assertion_01")))));
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException))]
        public void DetectSignature_02()
        {
            XmlDocument doc = LoadDocument(@"Assertions\EncryptedAssertion_01");
            doc.PreserveWhitespace = false;
            XmlSignatureUtils.IsSigned(doc);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CheckSignature_01()
        {
            XmlDocument doc = LoadDocument(@"Assertions\EncryptedAssertion_01");            
            XmlSignatureUtils.CheckSignature(doc);
        }

        [Test]        
        public void CheckSignature_02()
        {
            XmlDocument doc = LoadDocument(@"Assertions\Saml2Assertion_01");
            Assert.That(XmlSignatureUtils.CheckSignature(doc));
        }

        [Test]
        public void ExtractKeyInfo_01()
        {
            XmlDocument doc = LoadDocument(@"Assertions\Saml2Assertion_01");
            KeyInfo keyInfo = XmlSignatureUtils.ExtractSignatureKeys(doc); 
            Assert.IsNotNull(keyInfo);            
        }

        public static XmlDocument LoadDocument(string assertionFile)
        {
            FileStream fs = File.OpenRead(assertionFile);

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(fs);
            fs.Close();

            return document;
        }
    }
}