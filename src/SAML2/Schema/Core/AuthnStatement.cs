using System;
using System.Xml.Serialization;
using SAML2.Utils;

namespace SAML2.Schema.Core
{
    /// <summary>
    /// The &lt;AuthnStatement&gt; element describes a statement by the SAML authority asserting that the
    /// assertion subject was authenticated by a particular means at a particular time. Assertions containing
    /// &lt;AuthnStatement&gt; elements MUST contain a &lt;Subject&gt; element.
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.Assertion)]
    [XmlRoot(ElementName, Namespace = Saml20Constants.Assertion, IsNullable = false)]
    public class AuthnStatement : StatementAbstract
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public new const string ElementName = "AuthnStatement";

        /// <summary>
        /// Gets or sets the authn instant.
        /// Specifies the time at which the authentication took place. The time value is encoded in UTC
        /// </summary>
        /// <value>The authn instant.</value>
        [XmlIgnore]
        public DateTime? AuthnInstant { get; set; }

        /// <summary>
        /// Gets or sets the session not on or after.
        /// Specifies a time instant at which the session between the principal identified by the subject and the
        /// SAML authority issuing this statement MUST be considered ended. The time value is encoded in
        /// UTC, as described in Section 1.3.3. There is no required relationship between this attribute and a
        /// NotOnOrAfter condition attribute that may be present in the assertion.
        /// </summary>
        /// <value>The session not on or after.</value>
        [XmlIgnore]
        public DateTime? SessionNotOnOrAfter { get; set; }

        #region Attributes

        /// <summary>
        /// Gets or sets the authn instant string.
        /// </summary>
        /// <value>The authn instant string.</value>
        [XmlAttribute("AuthnInstant")]
        public string AuthnInstantString
        {
            get { return AuthnInstant.HasValue ? Saml20Utils.ToUtcString(AuthnInstant.Value) : null; }
            set { AuthnInstant = Saml20Utils.FromUtcString(value); }
        }

        /// <summary>
        /// Gets or sets the index of the session.
        /// Specifies the index of a particular session between the principal identified by the subject and the
        /// authenticating authority.
        /// </summary>
        /// <value>The index of the session.</value>
        [XmlAttribute("SessionIndex")]
        public string SessionIndex { get; set; }

        /// <summary>
        /// Gets or sets the session not on or after string.
        /// </summary>
        /// <value>The session not on or after string.</value>
        [XmlAttribute("SessionNotOnOrAfter")]
        public string SessionNotOnOrAfterString
        {
            get { return SessionNotOnOrAfter.HasValue ? Saml20Utils.ToUtcString(SessionNotOnOrAfter.Value) : null; }
            set { SessionNotOnOrAfter = string.IsNullOrEmpty(value) ? (DateTime?)null : Saml20Utils.FromUtcString(value); }
        }

        #endregion

        #region Elements

        /// <summary>
        /// Gets or sets the authn context.
        /// The context used by the authenticating authority up to and including the authentication event that
        /// yielded this statement. Contains an authentication context class reference, an authentication context
        /// declaration or declaration reference, or both. See the Authentication Context specification
        /// [SAMLAuthnCxt] for a full description of authentication context information.
        /// </summary>
        /// <value>The authn context.</value>
        [XmlElement("AuthnContext")]
        public AuthnContext AuthnContext { get; set; }

        /// <summary>
        /// Gets or sets the subject locality.
        /// Specifies the DNS domain name and IP address for the system from which the assertion subject was
        /// apparently authenticated.
        /// </summary>
        /// <value>The subject locality.</value>
        [XmlElement("SubjectLocality")]
        public SubjectLocality SubjectLocality { get; set; }

        #endregion
    }
}
