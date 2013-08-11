using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Metadata
{
    /// <summary>
    /// Key types enum
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Metadata)]
    public enum KeyTypes
    {
        /// <summary>
        /// encryption
        /// </summary>
        [XmlEnum("encryption")]
        Encryption,

        /// <summary>
        /// signing
        /// </summary>
        [XmlEnum("signing")]
        Signing
    }
}