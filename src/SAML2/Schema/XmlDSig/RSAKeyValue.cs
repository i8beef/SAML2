using System;
using System.Xml.Serialization;

namespace SAML2.Schema.XmlDSig
{
    /// <summary>
    /// RSA key values have two fields: Modulus and Exponent. 
    /// 
    /// &lt;RSAKeyValue&gt;
    ///      &lt;Modulus&gt;xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6W
    ///       jubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV
    ///       5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=
    ///      &lt;/Modulus&gt;
    ///      &lt;Exponent&gt;AQAB&lt;/Exponent&gt;
    ///    &lt;/RSAKeyValue&gt;
    ///    
    /// Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are represented in XML as octet strings as defined by the ds:CryptoBinary type. 
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.Xmldsig)]
    [XmlRoot(ElementName, Namespace=Saml20Constants.Xmldsig, IsNullable=false)]
    public class RSAKeyValue
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string ElementName = "RSAKeyValue";

        #region Elements

        /// <summary>
        /// Gets or sets the exponent.
        /// </summary>
        /// <value>The exponent.</value>
        [XmlElement("Exponent", DataType = "base64Binary")]
        public byte[] Exponent { get; set; }

        /// <summary>
        /// Gets or sets the modulus.
        /// </summary>
        /// <value>The modulus.</value>
        [XmlElement("Modulus", DataType = "base64Binary")]
        public byte[] Modulus { get; set; }

        #endregion
    }
}
