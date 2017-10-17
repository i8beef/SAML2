using System.Xml;
using NUnit.Framework;
using SAML2.Schema.Core;
using SAML2.Schema.XmlDSig;
using SAML2.Validation;

namespace SAML2.Tests.Validation
{
    /// <summary>
    /// <see cref="Saml20SubjectConfirmationValidator"/> tests.
    /// </summary>
    [TestFixture]
    public class Saml20SubjectConfirmationValidatorTests
    {
        /// <summary>
        /// ValidateSubjectConfirmation method tests.
        /// </summary>
        [TestFixture]
        public class ValidateSubjectConfirmationMethod
        {
            /// <summary>
            /// Tests the validation of the SubjectConfirmation element
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenSubjectConfirmationDataDoesNotContainKeyInfo()
            {
                // Arrange
                var subjectConfirmation = new SubjectConfirmation
                                              {
                                                  Method = Saml20Constants.SubjectConfirmationMethods.HolderOfKey,
                                                  SubjectConfirmationData = new SubjectConfirmationData()
                                              };

                var validator = new Saml20SubjectConfirmationValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateSubjectConfirmation(subjectConfirmation),
                    "SubjectConfirmationData element MUST have at least one " + KeyInfo.ElementName + " subelement");
            }

            /// <summary>
            /// Tests the validation of the SubjectConfirmation element's method attribute.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenSubjectConfirmationHasEmptyMethod()
            {
                // Arrange
                var subjectConfirmation = new SubjectConfirmation { Method = " " };
                var validator = new Saml20SubjectConfirmationValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateSubjectConfirmation(subjectConfirmation),
                    "Method attribute of SubjectConfirmation MUST contain at least one non-whitespace character");
            }

            /// <summary>
            /// Tests the validation of the SubjectConfirmation element's method attribute.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenSubjectConfirmationHasWrongMethod()
            {
                // Arrange
                var subjectConfirmation = new SubjectConfirmation { Method = "malformed uri" };
                var validator = new Saml20SubjectConfirmationValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateSubjectConfirmation(subjectConfirmation),
                    "SubjectConfirmation element has Method attribute which is not a wellformed absolute uri.");
            }

            /// <summary>
            /// Subjects the confirmation data_ method_ holder of key_ valid.
            /// </summary>
            [Test]
            public void ValidatesSubjectConfirmationData_Method_HolderOfKey_Valid()
            {
                // Arrange
                var subjectConfirmation = new SubjectConfirmation
                                              {
                                                  Method = Saml20Constants.SubjectConfirmationMethods.HolderOfKey,
                                                  SubjectConfirmationData = new SubjectConfirmationData()
                                              };
                var doc = new XmlDocument();
                var elem = doc.CreateElement("ds", "KeyInfo", Saml20Constants.Xmldsig);
                elem.AppendChild(doc.CreateElement("lalala"));

                subjectConfirmation.SubjectConfirmationData.AnyElements = new[] { elem };

                var validator = new Saml20SubjectConfirmationValidator();

                // Act
                validator.ValidateSubjectConfirmation(subjectConfirmation);
            }
        }
    }
}
