using System;
using System.Xml.Serialization;
using SAML2.Schema.Protocol;

namespace SAML2.Schema.Core
{
    /// <summary>
    /// The &lt;Evidence&gt; element contains one or more assertions or assertion references that the SAML
    /// authority relied on in issuing the authorization decision.
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.ASSERTION)]
    [XmlRoot(ElementName, Namespace=Saml20Constants.ASSERTION, IsNullable=false)]
    public class Evidence
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string ElementName = "Evidence";

        #region Elements

        /// <summary>
        /// Gets or sets the items.
        /// Items may be of types Assertion, AssertionIDRef, AssertionURIRef and EncryptedAssertion
        /// </summary>
        /// <value>The items.</value>
        [XmlElement("Assertion", typeof (Assertion))]
        [XmlElement("AssertionIDRef", typeof (string), DataType = "NCName")]
        [XmlElement("AssertionURIRef", typeof (string), DataType = "anyURI")]
        [XmlElement("EncryptedAssertion", typeof (EncryptedElement))]
        [XmlChoiceIdentifier("ItemsElementName")]
        public object[] Items { get; set; }

        /// <summary>
        /// Gets or sets the name of the items element.
        /// </summary>
        /// <value>The name of the items element.</value>
        [XmlElement("ItemsElementName")]
        [XmlIgnore]
        public EvidenceType[] ItemsElementName { get; set; }

        #endregion
    }
}
