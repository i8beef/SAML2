﻿using System.Collections.Generic;
using NUnit.Framework;
using SAML2.Schema.Core;
using SAML2.Validation;

namespace SAML2.Tests.Validation
{
    /// <summary>
    /// <see cref="Saml20SubjectValidator"/> tests.
    /// </summary>
    [TestFixture]
    public class Saml20SubjectValidatorTests
    {
        /// <summary>
        /// ValidateSubject method tests.
        /// </summary>
        [TestFixture]
        public class ValidateSubjectMethod
        {
            /// <summary>
            /// Tests the validation that ensures that a subject MUST have at least one sub element
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenSubjectConfirmationDoesNotContainSubject()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                saml20Assertion.Subject.Items = new object[] { };

                var validator = new Saml20SubjectValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateSubject(saml20Assertion.Subject),
                    "Subject MUST contain either an identifier or a subject confirmation");
            }

            /// <summary>
            /// Tests the validation that ensures that a subject MUST have at least one sub element of correct type
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenSubjectConfirmationContainsElementsOfWrongIdentifier()
            {
                // Arrange
                var saml20Assertion = AssertionUtil.GetBasicAssertion();
                saml20Assertion.Subject.Items = new object[] { string.Empty, 24, new List<object>(1), new Advice() };

                var validator = new Saml20SubjectValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateSubject(saml20Assertion.Subject),
                    "Subject must have either NameID, EncryptedID or SubjectConfirmation subelement.");
            }
        }
    }
}
