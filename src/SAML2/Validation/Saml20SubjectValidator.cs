using System;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;

namespace SAML2.Validation
{
    internal class Saml20SubjectValidator : ISaml20SubjectValidator
    {
        #region Properties

        private ISaml20NameIDValidator _nameIdValidator;

        private ISaml20NameIDValidator NameIdValidator
        {
            get
            {
                if (_nameIdValidator == null)
                    _nameIdValidator = new Saml20NameIDValidator();
                return _nameIdValidator;
            }
        }

        private ISaml20SubjectConfirmationValidator _subjectConfirmationValidator;

        private ISaml20SubjectConfirmationValidator SubjectConfirmationValidator
        {
            get
            {
                if (_subjectConfirmationValidator == null)
                    _subjectConfirmationValidator = new Saml20SubjectConfirmationValidator();
                return _subjectConfirmationValidator;
            }
        }

        #endregion

        public virtual void ValidateSubject(Subject subject)
        {
            if (subject == null) throw new ArgumentNullException("subject");

            bool validContentFound = false;

            if (subject.Items == null || subject.Items.Length == 0)
                throw new Saml20FormatException("Subject MUST contain either an identifier or a subject confirmation");

            foreach (object o in subject.Items)
            {
                if (o is NameID)
                {
                    validContentFound = true;
                    NameIdValidator.ValidateNameID((NameID)o);
                }
                else if (o is EncryptedElement)
                {
                    validContentFound = true;
                    NameIdValidator.ValidateEncryptedID((EncryptedElement)o);
                }
                else if (o is SubjectConfirmation)
                {
                    validContentFound = true;
                    SubjectConfirmationValidator.ValidateSubjectConfirmation((SubjectConfirmation)o);
                }
            }

            if (!validContentFound)
                throw new Saml20FormatException("Subject must have either NameID, EncryptedID or SubjectConfirmation subelement.");
        }
    }
}
