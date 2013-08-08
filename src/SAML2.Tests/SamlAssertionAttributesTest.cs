using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SAML2;
using SAML2.Schema.Core;
using NUnit.Framework;

namespace SAML2.Tests.Saml20
{
    /// <summary>
    /// Tests related to the handling of attributes on Saml Assertions.
    /// </summary>
    [TestFixture]
    public class SamlAssertionAttributesTest
    {
        #region Tests

        /// <summary>
        /// Adds an attribute to the assertion, signs it and verifies that the new attribute is part of the signed assertion.
        /// </summary>
        [Ignore]    // TODO: test data needs fixing
        public void AddAttribute_01()
        {
            Saml20Assertion assertion = LoadAssertion(@"Assertions\Saml2Assertion_01");
            List<SamlAttribute> attributes = assertion.Attributes;
            attributes.Add(new SamlAttribute());

            X509Certificate2 cert = AssertionUtil.GetCertificate1();
            assertion.Sign(cert);

            assertion.CheckValid(new AsymmetricAlgorithm[] { cert.PublicKey.Key });

            // Verify that the modified assertion can survive complete serialization and deserialization.
            string assertionString = assertion.GetXml().OuterXml;

            XmlDocument deserializedAssertionDoc = new XmlDocument();
            deserializedAssertionDoc.PreserveWhitespace = true;
            deserializedAssertionDoc.Load(new StringReader(assertionString));            

            Saml20Assertion deserializedAssertion = new Saml20Assertion(deserializedAssertionDoc.DocumentElement, null, false);
            Assert.IsNotNull(deserializedAssertion.GetSignatureKeys(), "Signing keys must be present");
            deserializedAssertion.CheckValid(new AsymmetricAlgorithm[] { cert.PublicKey.Key });
        }

        /// <summary>
        /// Load one of the test assertions and verify its number of attributes.
        /// </summary>
        [Test]
        public void ReadAttributes_01()
        {
            Saml20Assertion assertion = LoadAssertion(@"Assertions\Saml2Assertion_01");
            CollectionAssert.IsNotEmpty(assertion.Attributes);
            Assert.AreEqual(4, assertion.Attributes.Count);
            foreach(SamlAttribute sa in assertion.Attributes)
            {
                Assert.That(sa.AttributeValue.Length != 0, "Attribute should have a value");
                Assert.That(sa.AttributeValue[0] is string, "Attribute value must be a string");
            }
        }

        #endregion

        /// <summary>
        /// Creates a DKSaml20-token from a file. The token's signature is NOT verified on load.
        /// </summary>
        internal Saml20Assertion LoadAssertion(string file)
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(file);

            return new Saml20Assertion(document.DocumentElement, null, false);
        }
    }
}