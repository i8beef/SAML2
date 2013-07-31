using SAML2.Schema.Core;

namespace SAML2.Validation
{
    public interface ISaml20StatementValidator
    {
        void ValidateStatement(StatementAbstract statement);
    }
}