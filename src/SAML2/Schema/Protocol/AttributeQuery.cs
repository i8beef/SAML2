using System;
using System.Xml.Serialization;
using SAML2.Schema.Core;

namespace SAML2.Schema.Protocol
{
    /// <summary>
    /// The &lt;AttributeQuery&gt; element is used to make the query "Return the requested attributes for this
    /// subject." A successful response will be in the form of assertions containing attribute statements, to the
    /// extent allowed by policy.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Protocol)]
    [XmlRoot(ElementName, Namespace = Saml20Constants.Protocol, IsNullable = false)]
    public class AttributeQuery : SubjectQueryAbstract
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public new const string ElementName = "AttributeQuery";

        #region Elements

        /// <summary>
        /// Gets or sets the attribute.
        /// Each &lt;saml:Attribute&gt; element specifies an attribute whose value(s) are to be returned. If no
        /// attributes are specified, it indicates that all attributes allowed by policy are requested. If a given
        /// &lt;saml:Attribute&gt; element contains one or more &lt;saml:AttributeValue&gt; elements, then if
        /// that attribute is returned in the response, it MUST NOT contain any values that are not equal to the
        /// values specified in the query. In the absence of equality rules specified by particular profiles or
        /// attributes, equality is defined as an identical XML representation of the value
        /// </summary>
        /// <value>The attribute.</value>
        [XmlElement("Attribute", Namespace = Saml20Constants.Assertion)]
        public SamlAttribute[] SamlAttribute { get; set; }

        #endregion
    }
}
