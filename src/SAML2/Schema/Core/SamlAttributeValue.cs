using System;
using System.Xml;
using System.Xml.Serialization;

namespace SAML2.Schema.Core
{
    /// <summary>
    /// The &lt;Attribute&gt; element identifies an attribute by name and optionally includes its value(s). It has the
    /// AttributeType complex type. It is used within an attribute statement to express particular attributes and
    /// values associated with an assertion subject, as described in the previous section. It is also used in an
    /// attribute query to request that the values of specific SAML attributes be returned (see Section 3.3.2.3 for
    /// more information).
    /// </summary>
    [Serializable]    
    [XmlType(Namespace = Saml20Constants.Assertion)]
    [XmlRoot(ElementName, Namespace = Saml20Constants.Assertion, IsNullable = false)]
    public class SamlAttributeValue
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string ElementName = "AttributeValue";

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>The value.</value>
        [XmlText]
        public string Value { get; set; }

        #region Elements

        /// <summary>
        /// Gets or sets the any-elements-array.
        /// </summary>
        /// <value>The any-elements-array</value>
        [XmlAnyElement()]
        public XmlElement[] AnyElements { get; set; }

        #endregion
    }
}
