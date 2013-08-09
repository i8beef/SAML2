using System;
using System.Xml.Serialization;

namespace SAML2.Schema.XEnc
{
    /// <summary>
    /// ItemsChoice for Referencelists
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.XENC, IncludeInSchema=false)]
    public enum ReferenceListType
    {
        /// <summary>
        /// DataReference
        /// </summary>
        [XmlEnum("DataReference")]
        DataReference,

        /// <summary>
        /// KeyReference
        /// </summary>
        [XmlEnum("KeyReference")]
        KeyReference,
    }
}
