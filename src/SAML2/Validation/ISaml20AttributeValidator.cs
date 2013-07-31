using SAML2.Schema.Core;
using SAML2.Schema.Protocol;

namespace SAML2.Validation
{
    public interface ISaml20AttributeValidator
    {
        void ValidateAttribute(SamlAttribute samlAttribute);
        void ValidateEncryptedAttribute(EncryptedElement encryptedElement);
    }
}