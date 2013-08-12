using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using NUnit.Framework;
using SAML2.Schema.Core;

namespace SAML2.Tests
{
    /// <summary>
    /// <see cref="Saml20Assertion"/> tests.
    /// </summary>
    [TestFixture]
    public class Saml20AssertionTests
    {
        /// <summary>
        /// Constructor method tests.
        /// </summary>
        [TestFixture]
        public class ConstructorMethod
        {
            /// <summary>
            /// Adds an attribute to the assertion, signs it and verifies that the new attribute is part of the signed assertion.
            /// </summary>
            [Ignore]    // TODO: test data needs fixing
            public void AddAttribute_01()
            {
                var assertion = new Saml20Assertion(AssertionUtil.LoadXmlDocument(@"Assertions\Saml2Assertion_01").DocumentElement, null, false);
                var attributes = assertion.Attributes;
                attributes.Add(new SamlAttribute());

                var cert = AssertionUtil.GetCertificate();
                assertion.Sign(cert);

                assertion.CheckValid(new[] { cert.PublicKey.Key });

                // Verify that the modified assertion can survive complete serialization and deserialization.
                var assertionString = assertion.GetXml().OuterXml;

                var deserializedAssertionDoc = new XmlDocument { PreserveWhitespace = true };
                deserializedAssertionDoc.Load(new StringReader(assertionString));

                var deserializedAssertion = new Saml20Assertion(deserializedAssertionDoc.DocumentElement, null, false);
                Assert.IsNotNull(deserializedAssertion.GetSignatureKeys(), "Signing keys must be present");
                deserializedAssertion.CheckValid(new[] { cert.PublicKey.Key });
            }

            /// <summary>
            /// Load one of the test assertions and verify its number of attributes.
            /// </summary>
            [Test]
            public void ReadAttributes_01()
            {
                // Act
                var assertion = new Saml20Assertion(AssertionUtil.LoadXmlDocument(@"Assertions\Saml2Assertion_01").DocumentElement, null, false);

                // Asset
                CollectionAssert.IsNotEmpty(assertion.Attributes);
                Assert.AreEqual(4, assertion.Attributes.Count);
                foreach (var sa in assertion.Attributes)
                {
                    Assert.That(sa.AttributeValue.Length != 0, "Attribute should have a value");
                }
            }

            /// <summary>
            /// Test that the Assertion class verifies the signature of an assertion by default.
            /// </summary>
            [Test]
            [ExpectedException(typeof(InvalidOperationException), ExpectedMessage = "Document does not contain a signature to verify.")]
            public void VerifySignatureByDefault()
            {
                // Arrange
                // Any key-containing algorithm will do - the basic assertion is NOT signed anyway
                var cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

                // Act
                new Saml20Assertion(AssertionUtil.GetTestAssertion().DocumentElement, new[] { cert.PublicKey.Key }, false);
            }
        }
    }
}
