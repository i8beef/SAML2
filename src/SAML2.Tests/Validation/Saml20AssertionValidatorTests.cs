﻿using System;
using System.Collections.Generic;
using NUnit.Framework;
using SAML2.Schema.Core;
using SAML2.Validation;

namespace SAML2.Tests.Validation
{
    /// <summary>
    /// <see cref="Saml20AssertionValidator"/> tests.
    /// </summary>
    [TestFixture]
    public class Saml20AssertionValidatorTests
    {
        /// <summary>
        /// ValidateAssertionAttributes method tests.
        /// </summary>
        [TestFixture]
        public class ValidateAssertionAttributesMethod
        {
            /// <summary>
            /// Tests validation of missing ID attribute
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenIdNull()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                assertion.Id = null;

                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Assertion element must have the ID attribute set.");
            }

            /// <summary>
            /// Tests validation of Issuer Element format
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenIssuerFormatInvalid()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                assertion.Issuer.Format = "a non wellformed uri";

                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "NameID element has Format attribute which is not a wellformed absolute uri.");
            }

            /// <summary>
            /// Tests validation of required IssueInstant Element 
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenIssueInstantNull()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                assertion.IssueInstant = null;

                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Assertion element must have the IssueInstant attribute set.");
            }

            /// <summary>
            /// Tests validation of Issuer Element presence
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenIssuerNull()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                assertion.Issuer = null;

                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Assertion element must have an issuer element.");
            }

            /// <summary>
            /// Tests validation of wrong version attribute
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenWrongVersion()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                assertion.Version = "60";

                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Wrong value of version attribute on Assertion element");
            }

            /// <summary>
            /// Verify valid assertions can be validated.
            /// </summary>
            [Test]
            public void ValidatesAssertion()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                validator.ValidateAssertion(assertion);
            }
        }

        /// <summary>
        /// ValidateConditions method tests.
        /// </summary>
        [TestFixture]
        public class ValidateValidateConditionsMethod
        {
            /// <summary>
            /// Test that audience-restricted assertions are not valid if ANY of the audience restrictions is not met 
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAudienceRestrictionAnyAudienceRestrictionIsNotMet()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var audienceConditions = new List<ConditionAbstract>(assertion.Conditions.Items);
                var audienceRestriction = new AudienceRestriction
                                              {
                                                  Audience = new List<string>(new[] { "http://well/formed.uri" })
                                              };
                audienceConditions.Add(audienceRestriction);

                assertion.Conditions.Items = audienceConditions;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "The service is not configured to meet the given audience restrictions");
            }

            /// <summary>
            /// Test that audience-restricted assertions are not valid if the restriction values are incorrectly formatted
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAudienceRestrictionAudienceFormatIsInvalid()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var audienceRestriction = new AudienceRestriction
                                              {
                                                  Audience = new List<string>(new[] { "malformed uri" })
                                              };

                assertion.Conditions.Items = new List<ConditionAbstract>(new ConditionAbstract[] { audienceRestriction });

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Audience element has value which is not a wellformed absolute uri");
            }

            /// <summary>
            /// Test that services that are not configured with the right allowed audience URI's do not 
            /// consider audience-restricted assertions valid
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAudienceRestrictionDoesNotMatch()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var allowedAudienceUris = new List<string>
                                              {
                                                  "uri:lalal"
                                              };
                var validator = new Saml20AssertionValidator(allowedAudienceUris, false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "The service is not configured to meet the given audience restrictions");
            }

            /// <summary>
            /// Test that services that are not configured with any allowed audience URI's do not 
            /// consider audience-restricted assertions valid
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAudienceRestrictionIsNotConfigured()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(null, false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "The service is not configured to meet any audience restrictions");
            }

            /// <summary>
            /// Tests the validation that ensures the Count property to be a non-negative integer
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenProxyRestrictionCountIsNegative()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var conditions = new List<ConditionAbstract>
                                     {
                                         new ProxyRestriction { Count = "-1" }
                                     };
                conditions.AddRange(assertion.Conditions.Items);
                assertion.Conditions.Items = conditions;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Count attribute of ProxyRestriction MUST BE a non-negative integer");
            }

            /// <summary>
            /// Tests the validation that ensures the Count property to be a non-negative integer
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenProxyRestrictionAudienceIsInvalid()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var conditions = new List<ConditionAbstract>
                                     {
                                         new ProxyRestriction
                                             {
                                                 Audience = new[] { "urn:a.wellformed:uri", "http://another/wellformed/uri", "a malformed uri" }
                                             }
                                     };
                conditions.AddRange(assertion.Conditions.Items);
                assertion.Conditions.Items = conditions;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "ProxyRestriction Audience MUST BE a wellformed uri");
            }

            /// <summary>
            /// Tests the validation that ensures at most 1 OneTimeUse condition
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenThereAreMultipleOneTimeUse()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var conditions = new List<ConditionAbstract>
                                     {
                                         new OneTimeUse(),
                                         new OneTimeUse()
                                     };
                conditions.AddRange(assertion.Conditions.Items);
                assertion.Conditions.Items = conditions;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Assertion contained more than one condition of type OneTimeUse");
            }

            /// <summary>
            /// Tests the validation that ensures at most 1 ProxyRestriction condition
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenThereAreMultipleProxyRestriction()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var conditions = new List<ConditionAbstract>
                                     {
                                         new ProxyRestriction(),
                                         new ProxyRestriction()
                                     };
                conditions.AddRange(assertion.Conditions.Items);
                assertion.Conditions.Items = conditions;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateAssertion(assertion), "Assertion contained more than one condition of type ProxyRestriction");
            }
            
            /// <summary>
            /// Test that audience-restricted assertions are valid if ALL of the audience restrictions are met 
            /// </summary>
            [Test]
            public void ValidatesAudienceRestrictionWithMultipleAudienceRestrictions()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var audienceConditions = new List<ConditionAbstract>(assertion.Conditions.Items);
                var audienceRestriction = new AudienceRestriction
                                              {
                                                  Audience = new List<string>(new[] { "urn:borger.dk:id" })
                                              };
                audienceConditions.Add(audienceRestriction);

                assertion.Conditions.Items = audienceConditions;

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Test that audience-restricted assertions are valid if ANY of the audiences within a single audience
            /// restrictions is met
            /// </summary>
            [Test]
            public void ValidatesAudienceRestrictionWithSeveralAudiences()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                foreach (var audienceCondition in assertion.Conditions.Items)
                {
                    if (!(audienceCondition is AudienceRestriction))
                    {
                        continue;
                    }

                    var audienceRestriction = (AudienceRestriction)audienceCondition;
                    var audiences = new List<string>(audienceRestriction.Audience) { "http://well/formed.uri" };
                    audienceRestriction.Audience = audiences;
                    break;
                }

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Tests the validity of an assertion that contains a non-negative Count property
            /// </summary>
            [Test]
            public void ValidatesProxyRestrictionCount()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var conditions = new List<ConditionAbstract>
                                     {
                                         new ProxyRestriction { Count = "1" }
                                     };
                conditions.AddRange(assertion.Conditions.Items);
                assertion.Conditions.Items = conditions;

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Tests the validation that ensures the Count property to be a non-negative integer
            /// </summary>
            [Test]
            public void ValidatesProxyRestrictionAudience()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                var conditions = new List<ConditionAbstract>
                                     {
                                         new ProxyRestriction
                                             {
                                                 Audience = new[] { "urn:a.wellformed:uri", "http://another/wellformed/uri" }
                                             }
                                     };
                conditions.AddRange(assertion.Conditions.Items);
                assertion.Conditions.Items = conditions;

                // Act
                validator.ValidateAssertion(assertion);
            }
        }

        /// <summary>
        /// ValidateTimeRestrictions method tests.
        /// </summary>
        [TestFixture]
        public class ValidateTimeRestrictionsMethod
        {
            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have a SessionNotOnOrAfter attribute set in the future.
            /// </summary>
            [Test]
            [Ignore("Test data needs fixing")]
            public void ThrowsExceptionWhenAuthnStatementSessionNotOnOrAfterInPast()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var statements = new List<StatementAbstract>(assertion.Items);
                var authnStatement = new AuthnStatement
                                         {
                                             AuthnInstant = DateTime.UtcNow,
                                             SessionNotOnOrAfter = DateTime.UtcNow.AddHours(-1)
                                         };
                statements.Add(authnStatement);
                assertion.Items = statements.ToArray();

                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateTimeRestrictions(assertion, new TimeSpan()), "AuthnStatement attribute SessionNotOnOrAfter MUST be in the future");
            }

            /// <summary>
            /// Test validity of assertion when condition has an invalid NotOnOrAfter time restriction
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenTimeRestrictionNotOnOrAfterNow()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Test with NotOnOrAfter that pre-dates now 
                assertion.Conditions.NotBefore = null;
                assertion.Conditions.NotOnOrAfter = DateTime.UtcNow;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateTimeRestrictions(assertion, new TimeSpan()), "Conditions.NotOnOrAfter must not be in the past");
            }
        }

        /// <summary>
        /// ValidateConditionsInterval method tests.
        /// </summary>
        [TestFixture]
        public class ValidateConditionsIntervalMethod
        {
            /// <summary>
            /// Test validity of assertion when condition has an invalid NotBefore time restriction
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenTimeRestrictionNotBeforeIsInvalid()
            {
                // Arrange
                // Test with NotBefore that post-dates now 
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                assertion.Conditions.NotBefore = DateTime.Now.AddDays(1);
                assertion.Conditions.NotOnOrAfter = null;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateTimeRestrictions(assertion, new TimeSpan()), "Conditions.NotBefore must not be in the future");
            }

            /// <summary>
            /// Test validity of assertion when condition has an invalid NotOnOrAfter time restriction
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenTimeRestrictionNotOnOrAfterYesterday()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Test with NotOnOrAfter that pre-dates now 
                assertion.Conditions.NotBefore = null;
                assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(-1);

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateTimeRestrictions(assertion, new TimeSpan()), "Conditions.NotOnOrAfter must not be in the past");
            }

            /// <summary>
            /// Test validity of assertion when condition is time restricted in both directions
            /// </summary>
            [Test]
            public void ValidatesTimeRestrictionBothNotBeforeAndNotOnOrAfter()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                assertion.Conditions.NotBefore = DateTime.UtcNow.AddDays(-1);
                assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(1);

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Test validity of assertion when condition has a valid NotBefore time restriction
            /// </summary>
            [Test]
            public void ValidatesTimeRestrictionNotBeforeYesterday()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Test with NotBefore that pre-dates now 
                assertion.Conditions.NotBefore = DateTime.UtcNow.AddDays(-1);
                assertion.Conditions.NotOnOrAfter = null;

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Test validity of assertion when condition has a valid NotBefore time restriction
            /// </summary>
            [Test]
            public void ValidatesTimeRestrictionNotBeforeNow()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Test with NotBefore that pre-dates now 
                assertion.Conditions.NotBefore = DateTime.UtcNow;
                assertion.Conditions.NotOnOrAfter = null;

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Test validity of assertion when condition is not time restricted
            /// </summary>
            [Test]
            public void ValidatesTimeRestrictionNotSpecified()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                assertion.Conditions.NotBefore = null;
                assertion.Conditions.NotOnOrAfter = null;

                // Act
                validator.ValidateAssertion(assertion);
            }

            /// <summary>
            /// Test validity of assertion when condition has a valid NotOnOrAfter time restriction
            /// </summary>
            [Test]
            public void ValidatesTimeRestrictionNotOnOrAfterTomorrow()
            {
                // Arrange
                var assertion = AssertionUtil.GetBasicAssertion();
                var validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);

                // Test with NotOnOrAfter that post-dates now 
                assertion.Conditions.NotBefore = null;
                assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(1);

                // Act
                validator.ValidateAssertion(assertion);
            }
        }
    }
}
