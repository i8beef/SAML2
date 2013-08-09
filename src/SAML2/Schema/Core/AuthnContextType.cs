using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Core
{
    /// <summary>
    /// Item Choices
    /// </summary>
    [Serializable]
    [XmlTypeAttribute(Namespace = Saml20Constants.ASSERTION, IncludeInSchema = false)]
    public enum AuthnContextType
    {
        /// <summary>
        /// Item of type AuthnContextClassRef
        /// </summary>
        [XmlEnum("AuthnContextClassRef")]
        AuthnContextClassRef,

        /// <summary>
        /// Item of type AuthnContextDecl
        /// </summary>
        [XmlEnum("AuthnContextDecl")]
        AuthnContextDecl,

        /// <summary>
        /// Item of type AuthnContextDeclRef
        /// </summary>
        [XmlEnum("AuthnContextDeclRef")]
        AuthnContextDeclRef,
    }
}