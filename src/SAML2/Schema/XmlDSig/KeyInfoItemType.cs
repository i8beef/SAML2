using System;
using System.Xml.Serialization;

namespace SAML2.Schema.XmlDSig
{
    /// <summary>
    /// KeyInfo item types.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Xmldsig, IncludeInSchema = false)]
    public enum KeyInfoItemType
    {
        /// <summary>
        /// Any item type.
        /// </summary>
        [XmlEnum("##any:")]
        Item,
        
        /// <summary>
        /// KeyName item type.
        /// </summary>
        [XmlEnum("KeyName")]
        KeyName,
        
        /// <summary>
        /// KeyValue item type.
        /// </summary>
        [XmlEnum("KeyValue")]
        KeyValue,
        
        /// <summary>
        /// MgmtData item type.
        /// </summary>
        [XmlEnum("MgmtData")]
        MgmtData,
        
        /// <summary>
        /// PGPData item type.
        /// </summary>
        [XmlEnum("PGPData")]
        PGPData,
        
        /// <summary>
        /// RetrievalMethod item type.
        /// </summary>
        [XmlEnum("RetrievalMethod")]
        RetrievalMethod,
        
        /// <summary>
        /// SPKIData item type.
        /// </summary>
        [XmlEnum("SPKIData")]
        SPKIData,
        
        /// <summary>
        /// X509Data item type.
        /// </summary>
        [XmlEnum("X509Data")]
        X509Data
    }
}
