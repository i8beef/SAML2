using System;
using System.Collections.Generic;
using NUnit.Framework;
using SAML2.Schema.Core;
using SAML2.Validation;

namespace SAML2.Tests.Validation
{
    /// <summary>
    /// <see cref="Saml20StatementValidator"/> tests.
    /// </summary>
    [TestFixture]
    public class Saml20StatementValidatorTests
    {
        /// <summary>
        /// ValidateAttributeStatement method tests.
        /// </summary>
        [TestFixture]
        public class ValidateAttributeStatmentMethod
        {
            /// <summary>
            /// Verify exception is thrown on AttributeStatement Attribute list being null.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenNullAttributeList()
            {
                // Arrange
                var statement = new AttributeStatement();
                var validator = new Saml20StatementValidator();

                statement.Items = null;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AttributeStatement MUST contain at least one Attribute or EncryptedAttribute");
            }

            /// <summary>
            /// Verify exception is thrown on AttributeStatement containing no Attributes or EncryptedAttributes.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenEmptyAttributeList()
            {
                // Arrange
                var statement = new AttributeStatement();
                var validator = new Saml20StatementValidator();

                statement.Items = new object[0];

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AttributeStatement MUST contain at least one Attribute or EncryptedAttribute");
            }

            /// <summary>
            /// Verify that Attribute objects must have a non-empty Name
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAttributeElementEmptyName()
            {
                // Arrange
                var statement = new AttributeStatement();
                var validator = new Saml20StatementValidator();

                statement.Items = new object[] { new SamlAttribute() };

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "Name attribute of Attribute element MUST contain at least one non-whitespace character");
            }
        }

        /// <summary>
        /// ValidateAuthnStatement method tests.
        /// </summary>
        [TestFixture]
        public class ValidateAuthnStatmentMethod
        {
            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have an valid uri content for <c>AuthenticatingAuthority</c> entries
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextAuthenticatingAuthorityUriInvalid()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                statement.AuthnContext = new AuthnContext
                {
                    AuthenticatingAuthority = new[]
                    {
                        "urn:aksdlfj",
                        "urn/invalid"
                    },
                    Items = new object[]
                    {
                        "urn:a:valid.uri:string",
                        "http://another/valid/uri.string"
                    },
                    ItemsElementName = new[]
                    {
                        AuthnContextType.AuthnContextClassRef,
                        AuthnContextType.AuthnContextDeclRef
                    }
                };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthenticatingAuthority array contains a value which is not a wellformed absolute uri");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have a valid uri content for <c>AuthnContextClassRef</c> types
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextAuthnContextClassRefUriInvalid()
            {
                // Arrange
                var statement = new AuthnStatement
                {
                    AuthnInstant = DateTime.UtcNow,
                    SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                };
                statement.AuthnContext = new AuthnContext
                {
                    Items = new object[]
                    {
                        string.Empty,
                        "urn:a.valid.uri:string"
                    },
                    ItemsElementName = new[]
                    {
                        AuthnContextType.AuthnContextClassRef,
                        AuthnContextType.AuthnContextDeclRef
                    }
                };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContextClassRef has a value which is not a wellformed absolute uri");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects MUST NOT have content of type <c>AuthnContextDecl</c>
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextAuthnContextDeclInvalid()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                statement.AuthnContext = new AuthnContext
                                             {
                                                 Items = new object[]
                                                             {
                                                                 new AuthnStatement()
                                                             },
                                                 ItemsElementName = new[]
                                                                        {
                                                                            AuthnContextType.AuthnContextDecl
                                                                        }
                                             };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContextDecl elements are not allowed in this implementation");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have a valid uri content for <c>AuthnContextDeclRef</c> types
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextAuthnContextDeclRefUriInvalid()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                statement.AuthnContext = new AuthnContext
                                             {
                                                 Items = new object[]
                                                             {
                                                                 "urn:a.valid.uri:string",
                                                                 "an/invalid/uri/string.aspx"
                                                             },
                                                 ItemsElementName = new[]
                                                                        {
                                                                            AuthnContextType.AuthnContextClassRef,
                                                                            AuthnContextType.AuthnContextDeclRef
                                                                        }
                                             };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContextDeclRef has a value which is not a wellformed absolute uri");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have a <c>AuthnContextClassRef</c> type as the first element if it is present
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextFirstItemNotAuthnContextClassRef()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                statement.AuthnContext = new AuthnContext
                                             {
                                                 Items = new object[]
                                                             {
                                                                 "urn:a.valid.uri:string",
                                                                 "urn:a.valid.uri:string"
                                                             },
                                                 ItemsElementName = new[]
                                                                        {
                                                                            AuthnContextType.AuthnContextDeclRef,
                                                                            AuthnContextType.AuthnContextClassRef
                                                                        }
                                             };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContextClassRef must be in the first element");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have no more than 2 {<c>AuthnContextClassRef</c>, <c>AuthnContextDeclRef</c>} elements
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextHasMoreThanTwoItems()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                statement.AuthnContext = new AuthnContext
                                             {
                                                 Items = new object[]
                                                             {
                                                                 "urn:a.valid.uri:string",
                                                                 "urn:a.valid.uri:string",
                                                                 "urn:a.valid.uri:string"
                                                             },
                                                 ItemsElementName = new[]
                                                                        {
                                                                            AuthnContextType.AuthnContextDeclRef,
                                                                            AuthnContextType.AuthnContextDeclRef,
                                                                            AuthnContextType.AuthnContextDeclRef
                                                                        }
                                             };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContext MUST NOT contain more than two elements.");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have non-null contents
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextItemsEmpty()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                statement.AuthnContext = new AuthnContext
                                             {
                                                 Items = new List<object>().ToArray(),
                                                 ItemsElementName = new List<AuthnContextType>().ToArray()
                                             };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContext element MUST contain at least one AuthnContextClassRef, AuthnContextDecl or AuthnContextDeclRef element");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have non-empty contents
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextItemsNull()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnContext = new AuthnContext(),
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnContext element MUST contain at least one AuthnContextClassRef, AuthnContextDecl or AuthnContextDeclRef element");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have an <c>AuthnContext</c> element
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnContextNull()
            {
                // Arrange
                var statement = new AuthnStatement
                                    {
                                        AuthnInstant = DateTime.UtcNow,
                                        SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1)
                                    };
                var validator = new Saml20StatementValidator();

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnStatement MUST have an AuthnContext element");
            }

            /// <summary>
            /// Tests that <c>AuthnStatement</c> objects must have an <c>AuthnInstant</c> attribute.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenAuthnInstantNull()
            {
                // Arrange
                var statement = new AuthnStatement();
                var validator = new Saml20StatementValidator();

                statement.AuthnInstant = null;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "AuthnStatement MUST have an AuthnInstant attribute");
            }
        }

        /// <summary>
        /// ValidateDecisionStatement method tests.
        /// </summary>
        [TestFixture]
        public class ValidateDecisionStatementMethod
        {
            /// <summary>
            /// Verify exception is thrown on malformed resource URI.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenMalformedResource()
            {
                // Arrange
                var statement = new AuthzDecisionStatement();
                var validator = new Saml20StatementValidator();

                statement.Resource = "a malformed uri";

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "Resource attribute of AuthzDecisionStatement has a value which is not a wellformed absolute uri");
            }

            /// <summary>
            /// Verify exception is thrown on missing <c>AuthzDecisionStatement</c>.
            /// </summary>
            [Test]
            public void ThrowsExceptionWhenMissingResourceEmpty()
            {
                // Arrange
                var statement = new AuthzDecisionStatement();
                var validator = new Saml20StatementValidator();

                statement.Resource = null;

                // Act
                Assert.Throws<Saml20FormatException>(() => validator.ValidateStatement(statement),
                    "Resource attribute of AuthzDecisionStatement is REQUIRED");
            }

            /// <summary>
            /// Validates valid decision statements.
            /// </summary>
            [Test]
            public void ValidatesResources()
            {
                // Arrange
                var statement = new AuthzDecisionStatement();
                var validator = new Saml20StatementValidator();

                statement.Resource = string.Empty;
                var action = new Schema.Core.Action { Namespace = "http://valid/namespace" };
                statement.Action = new[] { action };
                validator.ValidateStatement(statement);

                statement.Resource = "urn:valid.ok:askjld";

                // Act
                validator.ValidateStatement(statement);
            }
        }
    }
}
