using SAML2.Schema.Core;

namespace SAML2.Validation
{
    interface ISaml20SubjectValidator
    {
        void ValidateSubject(Subject subject);
    }
}