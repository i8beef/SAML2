using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Metadata
{
    /// <summary>
    /// Contact type enum
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Metadata)]
    public enum ContactType
    {
        /// <summary>
        /// technical
        /// </summary>
        [XmlEnum("technical")]
        Technical,
        
        /// <summary>
        /// support
        /// </summary>
        [XmlEnum("support")]
        Support,
        
        /// <summary>
        /// administrative
        /// </summary>
        [XmlEnum("administrative")]
        Administrative,
        
        /// <summary>
        /// billing
        /// </summary>
        [XmlEnum("billing")]
        Billing,
        
        /// <summary>
        /// other
        /// </summary>
        [XmlEnum("other")]
        Other
    }
}