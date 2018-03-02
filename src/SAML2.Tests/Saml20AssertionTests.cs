using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using NUnit.Framework;
using SAML2.Exceptions;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Schema.XEnc;

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
            #region Attribute

            /// <summary>
            /// Adds an attribute to the assertion, signs it and verifies that the new attribute is part of the signed assertion.
            /// </summary>
            [Test]
            [Ignore("test data needs fixing")]
            public void AddAttribute()
            {
                // Arrange
                var assertion = new Saml20Assertion(AssertionUtil.LoadXmlDocument(TestContext.CurrentContext.TestDirectory + @"\Assertions\Saml2Assertion_01").DocumentElement, null, false);
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
            public void CanReadAttributes()
            {
                // Act
                var assertion = new Saml20Assertion(AssertionUtil.LoadXmlDocument(TestContext.CurrentContext.TestDirectory + @"\Assertions\Saml2Assertion_01").DocumentElement, null, false);

                // Assert
                CollectionAssert.IsNotEmpty(assertion.Attributes);
                Assert.AreEqual(4, assertion.Attributes.Count);
                foreach (var sa in assertion.Attributes)
                {
                    Assert.That(sa.AttributeValue.Length != 0, "Attribute should have a value");
                }
            }

            #endregion

            #region Signature

            /// <summary>
            /// Test that the Assertion class verifies the signature of an assertion by default.
            /// </summary>
            [Test]
            public void VerifySignatureByDefault()
            {
                // Arrange
                // Any key-containing algorithm will do - the basic assertion is NOT signed anyway
                var cert = new X509Certificate2(TestContext.CurrentContext.TestDirectory + @"\Certificates\sts_dev_certificate.pfx", "test1234");

                // Act
                Assert.Throws<InvalidOperationException>(() => new Saml20Assertion(AssertionUtil.GetTestAssertion().DocumentElement, new[] { cert.PublicKey.Key }, false),
                    "Document does not contain a signature to verify.");
            }

            #endregion

            #region Statements - Attribute

            /// <summary>
            /// Throws exception when no items are present.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenNoItemsArePresent()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var attributeStatement = (AttributeStatement)Array.Find(saml20Assertion.Items, x => x is AttributeStatement);

                // Clear all the attributes.
                attributeStatement.Items = new object[0];

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false),
                    "AttributeStatement MUST contain at least one Attribute or EncryptedAttribute");
            }

            /// <summary>
            /// Test that xml attribute extensions on Attribute objects must be namespace qualified
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenXmlAttributeStatementAttributeAnyAttrUnqualified()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var statements = new List<StatementAbstract>(saml20Assertion.Items);
                var attributeStatments = (AttributeStatement)statements.Find(x => x is AttributeStatement);
                var attribute = (SamlAttribute)attributeStatments.Items[0];

                var doc = new XmlDocument();
                attribute.AnyAttr = new[] { doc.CreateAttribute(string.Empty, "Nonqualified", string.Empty) };

                saml20Assertion.Items = statements.ToArray();

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false),
                    "Attribute extension xml attributes MUST BE namespace qualified");
            }

            /// <summary>
            /// Test that xml attribute extensions on Attribute objects must be namespace qualified
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenXmlAttributeStatementAttributeAnyAttrSamlQualified()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var statements = new List<StatementAbstract>(saml20Assertion.Items);
                var attributeStatments = (AttributeStatement)statements.Find(x => x is AttributeStatement);
                var attribute = (SamlAttribute)attributeStatments.Items[0];

                var doc = new XmlDocument();
                saml20Assertion.Items = statements.ToArray();

                foreach (var samlns in Saml20Constants.SamlNamespaces)
                {
                    attribute.AnyAttr = new[] { doc.CreateAttribute("someprefix", "SamlQualified", samlns) };

                    // Act
                    Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false),
                        "Attribute extension xml attributes MUST NOT use a namespace reserved by SAML");
                }
            }

            /// <summary>
            /// Test that EncryptedAttribute objects must have an EncryptedData child element
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenXmlAttributeStatementEncryptedAttributeWithNoData()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var statements = new List<StatementAbstract>(saml20Assertion.Items);
                var attributeStatments = (AttributeStatement)statements.Find(x => x is AttributeStatement);

                var attributes = new List<object>(attributeStatments.Items);
                var ee = new EncryptedElement();
                attributes.Add(ee);
                attributeStatments.Items = attributes.ToArray();
                saml20Assertion.Items = statements.ToArray();

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false),
                    "An EncryptedAttribute MUST contain an xenc:EncryptedData element");
            }

            /// <summary>
            /// Test that EncryptedData element must have the correct Type value
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenXmlAttributeStatementEncryptedAttributeWrongType()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var statements = new List<StatementAbstract>(saml20Assertion.Items);
                var attributeStatments = (AttributeStatement)statements.Find(x => x is AttributeStatement);

                var attributes = new List<object>(attributeStatments.Items);
                var ee = new EncryptedElement
                             {
                                 EncryptedData = new EncryptedData
                                                     {
                                                         Type = "SomeWrongType"
                                                     }
                             };
                attributes.Add(ee);
                attributeStatments.Items = attributes.ToArray();
                saml20Assertion.Items = statements.ToArray();

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false),
                    "Type attribute of EncryptedData MUST have value " + Saml20Constants.Xenc + "Element" + " if it is present");
            }

            #endregion

            #region Statements - AuthnStatement

            /// <summary>
            /// Throws exception when <c>AuthnContextClassRef</c> is not well formed URI.
            /// </summary>
            [Test]
            public void ThrowsWhenAuthnContextClassRefIsNotWellFormedUri()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var authnStatement = (AuthnStatement)Array.Find(saml20Assertion.Items, stmnt => stmnt is AuthnStatement);

                var index = Array.FindIndex(authnStatement.AuthnContext.Items, o => o is string && o.ToString() == "urn:oasis:names:tc:SAML:2.0:ac:classes:X509");
                authnStatement.AuthnContext.Items[index] = "Hallelujagobble!!";

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false),
                    "AuthnContextClassRef has a value which is not a wellformed absolute uri");
            }

            #endregion

            #region Subject

            /// <summary>
            /// Throws exception when subject element is not present.
            /// </summary>
            [Test]
            public void ThrowsWhenSubjectElementIsNotPresent()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var subjectConfirmation = (SubjectConfirmation)Array.Find(saml20Assertion.Subject.Items, item => item is SubjectConfirmation);
                subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow;
                subjectConfirmation.SubjectConfirmationData.NotBefore = null;
                saml20Assertion.Subject = null;

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false), 
                    "AuthnStatement, AuthzDecisionStatement and AttributeStatement require a subject.");
            }

            /// <summary>
            /// Throws exception when subject method is not well formed URI.
            /// </summary>
            [Test]
            public void ThrowsWhenSubjectMethodIsNotWellFormedUri()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                var subjectConfirmation = (SubjectConfirmation)Array.Find(saml20Assertion.Subject.Items, item => item is SubjectConfirmation);
                subjectConfirmation.Method = "IllegalMethod";

                // Act
                Assert.Throws<Saml20FormatException>(() => new Saml20Assertion(AssertionUtil.ConvertAssertionToXml(saml20Assertion).DocumentElement, null, false), 
                    "SubjectConfirmation element has Method attribute which is not a wellformed absolute uri.");
            }

            #endregion
        }
    }
}
