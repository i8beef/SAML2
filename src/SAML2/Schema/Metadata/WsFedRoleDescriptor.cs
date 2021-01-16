using System;
using System.Xml.Serialization;

namespace SAML2.Schema.Metadata
{
    /// <summary>
    /// Place holder for WsFed extension RoleDescriptor.
    /// </summary>
    [Serializable]
    [XmlType(TypeName = "SecurityTokenServiceType", Namespace = "http://docs.oasis-open.org/wsfed/federation/200706")]
    [XmlRoot(ElementName, Namespace = "http://docs.oasis-open.org/wsfed/federation/200706", IsNullable = false)]
    public class WsFedRoleDescriptor : RoleDescriptor
    {
    }
}
