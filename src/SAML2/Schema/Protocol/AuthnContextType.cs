using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Protocol
{
    /// <summary>
    /// AuthContext type enumeration.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Protocol, IncludeInSchema = false)]
    public enum AuthnContextType
    {
        /// <summary>
        /// AuthnContextClassRef type.
        /// </summary>
        [XmlEnum("urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextClassRef")]
        AuthnContextClassRef,

        /// <summary>
        /// AuthnContextDeclRef type.
        /// </summary>
        [XmlEnum("urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextDeclRef")]
        AuthnContextDeclRef
    }
}
