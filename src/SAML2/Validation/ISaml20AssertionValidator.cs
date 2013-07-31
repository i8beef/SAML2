using System;
using SAML2.Schema.Core;

namespace SAML2.Validation
{
    public interface ISaml20AssertionValidator
    {
        void ValidateAssertion(Assertion assertion);
        void ValidateTimeRestrictions(Assertion assertion, TimeSpan allowedClockSkew);
    }
}