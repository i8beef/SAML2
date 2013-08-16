using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Core
{
    /// <summary>
    /// The Saml20 StatementAbstract class. It's the baseclass for all statements in Saml20.
    /// </summary>
    [XmlInclude(typeof(AttributeStatement))]
    [XmlIncludeAttribute(typeof(AuthzDecisionStatement))]
    [XmlIncludeAttribute(typeof(AuthnStatement))]
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Assertion)]
    [XmlRoot(ElementName, Namespace = Saml20Constants.Assertion, IsNullable = false)]
    public abstract class StatementAbstract
    {        
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string ElementName = "Statement";
    }
}