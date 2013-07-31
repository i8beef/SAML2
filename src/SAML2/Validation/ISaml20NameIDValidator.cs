using SAML2.Schema.Core;
using SAML2.Schema.Protocol;

namespace SAML2.Validation
{
    public interface ISaml20NameIDValidator
    {
        void ValidateNameID(NameID nameID);
        void ValidateEncryptedID(EncryptedElement encryptedID);
    }
}