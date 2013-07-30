using System;
using System.Xml.Serialization;
using SAML2.Schema.Core;

namespace SAML2.Schema.Protocol
{
    /// <summary>
    /// The &lt;Response&gt; message element is used when a response consists of a list of zero or more assertions
    /// that satisfy the request. It has the complex type ResponseType, which extends StatusResponseType
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.PROTOCOL)]
    [XmlRoot(ELEMENT_NAME, Namespace=Saml20Constants.PROTOCOL, IsNullable=false)]
    public class Response : StatusResponse
    {

        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public new const string ELEMENT_NAME = "Response";

        private object[] itemsField;


        /// <summary>
        /// Gets or sets the items.
        /// Specifies an assertion by value, or optionally an encrypted assertion by value.
        /// </summary>
        /// <value>The items.</value>
        [XmlElement("Assertion", typeof (Assertion), Namespace=Saml20Constants.ASSERTION)]
        [XmlElement("EncryptedAssertion", typeof (EncryptedElement),
            Namespace=Saml20Constants.ASSERTION)]
        public object[] Items
        {
            get { return itemsField; }
            set { itemsField = value; }
        }
    }
}