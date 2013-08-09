using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using NUnit.Framework;
using SAML2;
using Saml20Assertion=SAML2.Saml20Assertion;

namespace SAML2.Tests.Saml20
{
    /// <summary>
    /// This class contains tests that can only be used when a Ping Identity server is running. 
    /// </summary>
    [TestFixture]
    [Explicit]    
    public class PingCompatibilityTest
    {
        [Test]
        public void DecryptPingAssertion()
        {
            // Load the assertion
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(@"c:\tmp\pingassertion.txt"));

            XmlElement xe = GetElement(EncryptedAssertion.ElementName, Saml20Constants.ASSERTION, doc);

            XmlDocument doc2 = new XmlDocument();
            doc2.AppendChild(doc2.ImportNode(xe, true));

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection coll = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName,
                                                                      "CN=SafewhereTest_SFS, O=Safewhere, C=DK", true);

            Assert.That(coll.Count == 1);

            X509Certificate2 cert = coll[0];

            Saml20EncryptedAssertion encass = new Saml20EncryptedAssertion((RSA)cert.PrivateKey, doc2);
            
            encass.Decrypt();
            
            XmlTextWriter writer = new XmlTextWriter(Console.Out);
            writer.Formatting = Formatting.Indented;
            writer.Indentation = 3;
            writer.IndentChar = ' ';

            encass.Assertion.WriteTo(writer);
            writer.Flush();
            
            Saml20Assertion assertion = new Saml20Assertion(encass.Assertion.DocumentElement, AssertionUtil.GetTrustedSigners(encass.Assertion.Attributes["Issuer"].Value), false);

            Assert.That(encass.Assertion != null);

            Console.WriteLine();
            foreach (SamlAttribute attribute in assertion.Attributes)            
                Console.WriteLine(attribute.Name + " : " + attribute.AttributeValue[0]);
            
        }

        private static XmlElement GetElement(string element, string ns, XmlDocument doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(element, ns);
            Assert.That(list.Count == 1);

            return (XmlElement)list[0];
        }
    }
}