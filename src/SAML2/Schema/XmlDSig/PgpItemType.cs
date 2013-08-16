using System;
using System.Xml.Serialization;

namespace SAML2.Schema.XmlDSig
{
    /// <summary>
    /// PGP item type.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Xmldsig, IncludeInSchema = false)]
    public enum PgpItemType
    {
        /// <summary>
        /// Any item type.
        /// </summary>
        [XmlEnum("##any:")]
        Item,

        /// <summary>
        /// PgpKeyId item type.
        /// </summary>
        [XmlEnum("PGPKeyID")]
        PgpKeyId,

        /// <summary>
        /// PgpKeyPacket item type.
        /// </summary>
        [XmlEnum("PGPKeyPacket")]
        PgpKeyPacket,
    }
}
