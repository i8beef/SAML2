using System;
using System.Xml.Serialization;
using SAML2.Schema.XEnc;

namespace SAML2.Schema.Protocol
{
    /// <summary>
    /// Represents an encrypted element
    /// </summary>
    /// <remarks>
    /// NOTE: XmlRoot parameter manually changed from "NewEncryptedID" to "EncryptedElementType".
    /// </remarks>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.ASSERTION)]
    [XmlRoot(ElementName, Namespace = Saml20Constants.ASSERTION, IsNullable = false)]
    [XmlInclude(typeof(EncryptedAssertion))]
    public class EncryptedElement
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string ElementName = "EncryptedElement";

        #region Elements

        /// <summary>
        /// Gets or sets the encrypted data.
        /// </summary>
        /// <value>The encrypted data.</value>
        [XmlElement("EncryptedData", Namespace=Saml20Constants.XENC)]
        public EncryptedData EncryptedData { get; set; }

        /// <summary>
        /// Gets or sets the encrypted key.
        /// </summary>
        /// <value>The encrypted key.</value>
        [XmlElement("EncryptedKey", Namespace=Saml20Constants.XENC)]
        public EncryptedKey[] EncryptedKey { get; set; }

        #endregion
    }
}
