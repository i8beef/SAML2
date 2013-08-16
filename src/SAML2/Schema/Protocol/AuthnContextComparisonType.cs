using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Protocol
{
    /// <summary>
    /// AuthContext comparison type enum.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.Protocol)]
    public enum AuthnContextComparisonType
    {
        /// <summary>
        /// Exact.
        /// </summary>
        [XmlEnum("exact")]
        Exact,

        /// <summary>
        /// Minimum.
        /// </summary>
        [XmlEnum("minimum")]
        Minimum,

        /// <summary>
        /// Maximum.
        /// </summary>
        [XmlEnum("maximum")]
        Maximum,

        /// <summary>
        /// Better.
        /// </summary>
        [XmlEnum("better")]
        Better
    }
}
