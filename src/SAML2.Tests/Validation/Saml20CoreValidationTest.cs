using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.Serialization;
using SAML2.Config;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Schema.XEnc;
using SAML2.Schema.XmlDSig;
using SAML2.Utils;
using SAML2.Validation;
using NUnit.Framework;
using Action = SAML2.Schema.Core.Action;
using AuthnContextType = SAML2.Schema.Core.AuthnContextType;

namespace SAML2.Tests.Validation
{
    ///<summary>
    /// Tests Saml20 core validation 
    ///</summary>
    [TestFixture]
    public class Saml20CoreValidationTest
    {
        #region Basic assertion tests

        #endregion

        #region Conditions tests

        #endregion

        #region Subject and Subject confirmation tests

        /// <summary>
        /// Tests the validation that ensures that a subject MUST have at least one subelement
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Subject MUST contain either an identifier or a subject confirmation")]
        public void SubjectConfirmation()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            saml20Assertion.Subject.Items = new object[] { };

            Saml20SubjectValidator validator = new Saml20SubjectValidator();
            validator.ValidateSubject(saml20Assertion.Subject);
        }

        /// <summary>
        /// Tests the validation that ensures that a subject MUST have at least one subelement of correct type
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Subject must have either NameID, EncryptedID or SubjectConfirmation subelement.")]
        public void SubjectConfirmation_WrongIdentifier()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Subject.Items = new object[] { String.Empty, 24, new List<object>(1), new Advice() };

            Saml20SubjectValidator validator = new Saml20SubjectValidator();
            validator.ValidateSubject(saml20Assertion.Subject);
        }

        /// <summary>
        /// Tests the validation of the SubjectConfirmation element's method attribute.
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Method attribute of SubjectConfirmation MUST contain at least one non-whitespace character")]
        public void SubjectConfirmationEmptyMethod()
        {
            SubjectConfirmation sct = new SubjectConfirmation();
            sct.Method = " ";
            Saml20SubjectConfirmationValidator validator = new Saml20SubjectConfirmationValidator();
            validator.ValidateSubjectConfirmation(sct);
        }

        /// <summary>
        /// Tests the validation of the SubjectConfirmation element's method attribute.
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmation element has Method attribute which is not a wellformed absolute uri.")]
        public void SubjectConfirmationWrongMethod()
        {
            SubjectConfirmation sct = new SubjectConfirmation();
            sct.Method = "malformed uri";
            Saml20SubjectConfirmationValidator validator = new Saml20SubjectConfirmationValidator();
            validator.ValidateSubjectConfirmation(sct);
        }

        /// <summary>
        /// Tests the validation of the SubjectConfirmationData recipient element
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Recipient of SubjectConfirmationData must be a wellformed absolute URI.")]
        public void SubjectConfirmationDataEmptyRecipient()
        {
            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
            subjectConfirmationData.Recipient = " ";

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        /// <summary>
        /// Tests the validation of the SubjectConfirmationData recipient element
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Recipient of SubjectConfirmationData must be a wellformed absolute URI.")]
        public void SubjectConfirmationDataInvalidRecipient()
        {
            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
            subjectConfirmationData.Recipient = "malformed uri";

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        /// <summary>
        /// Tests the validation of the SubjectConfirmationData recipient element
        /// </summary>
        [Test]
        public void SubjectConfirmationDataValidRecipient()
        {
            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);


        }

        /// <summary>
        /// Tests the validation of the SubjectConfirmationData {NotBefore, NotOnOrAfter} attributes
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NotBefore 2008-01-30T17:13:00.5Z MUST BE less than NotOnOrAfter 2008-01-30T16:13:00.5Z on SubjectConfirmationData")]
        public void SubjectConfirmationDataInvalidTimeInterval()
        {
            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
            subjectConfirmationData.NotBefore = new DateTime(2008, 01, 30, 17, 13, 0, 500, DateTimeKind.Utc);
            subjectConfirmationData.NotOnOrAfter = subjectConfirmationData.NotBefore.Value.AddHours(-1);

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }
        /// <summary>
        /// Tests the validation of the SubjectConfirmationData {NotBefore, NotOnOrAfter} attributes
        /// </summary>
        [Test]
        public void SubjectConfirmationDataValidTimeIntervalSettings()
        {
            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();

            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
            subjectConfirmationData.NotBefore = new DateTime(2008, 01, 30, 17, 13, 0, 500, DateTimeKind.Utc);
            subjectConfirmationData.NotOnOrAfter = subjectConfirmationData.NotBefore.Value.AddHours(1);

            validator.ValidateSubjectConfirmationData(subjectConfirmationData);

            subjectConfirmationData.NotBefore = null;
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);

            // DateTime validation wrt DateTime.UtcNow is NOT done by the validators
            // so a future-NotBefore must be valid
            subjectConfirmationData.NotBefore = subjectConfirmationData.NotOnOrAfter;
            subjectConfirmationData.NotOnOrAfter = null;
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);

            subjectConfirmationData.NotBefore = null;
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST have at least one " + KeyInfo.ElementName + " subelement")]
        public void SubjectConfirmationData_Invalid_KeyInfoConfirmationData_NoAnyElement()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST contain at least one " + KeyInfo.ElementName + " in namespace " + Saml20Constants.Xmldsig)]
        public void SubjectConfirmationData_Invalid_KeyInfoConfirmationData_IncompleteAnyElement()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";
            XmlDocument doc = new XmlDocument();
            subjectConfirmationData.AnyElements = new XmlElement[] { doc.CreateElement("ds", "KeyInfo", "http://wrongNameSpace.uri") };

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }


        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "KeyInfo subelement of SubjectConfirmationData MUST NOT be empty")]
        public void SubjectConfirmationData_Invalid_KeyInfoConfirmationData_IncompleteAnyElement_NoChildren()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";
            XmlDocument doc = new XmlDocument();
            subjectConfirmationData.AnyElements = new XmlElement[] { doc.CreateElement("ds", "KeyInfo", Saml20Constants.Xmldsig) };

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST contain at least one " + KeyInfo.ElementName + " in namespace " + Saml20Constants.Xmldsig)]
        public void SubjectConfirmationData_Invalid_KeyInfoConfirmationData_WrongAnyElement()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";
            XmlDocument doc = new XmlDocument();
            XmlElement elem = doc.CreateElement("ds", "KeyInfo", "http://wrongNameSpace.uri");
            elem.AppendChild((doc.CreateElement("ds", "KeyName", Saml20Constants.Xmldsig)));

            subjectConfirmationData.AnyElements = new XmlElement[] { elem };

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        public void SubjectConfirmationData_Valid_KeyInfoConfirmationData()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";
            XmlDocument doc = new XmlDocument();
            XmlElement elem = doc.CreateElement("ds", "KeyInfo", Saml20Constants.Xmldsig);
            elem.AppendChild((doc.CreateElement("lalala")));

            subjectConfirmationData.AnyElements = new XmlElement[] { elem };

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST have at least one " + KeyInfo.ElementName + " subelement")]
        public void SubjectConfirmationData_Method_HolderOfKey_Invalid_NoKeyInfo()
        {
            SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
            subjectConfirmation.Method = Saml20Constants.SubjectConfirmationMethods.HolderOfKey;
            subjectConfirmation.SubjectConfirmationData = new SubjectConfirmationData();

            Saml20SubjectConfirmationValidator validator = new Saml20SubjectConfirmationValidator();
            validator.ValidateSubjectConfirmation(subjectConfirmation);
        }

        [Test]
        public void SubjectConfirmationData_Method_HolderOfKey_Valid()
        {
            SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
            subjectConfirmation.Method = Saml20Constants.SubjectConfirmationMethods.HolderOfKey;
            subjectConfirmation.SubjectConfirmationData = new SubjectConfirmationData();
            XmlDocument doc = new XmlDocument();
            XmlElement elem = doc.CreateElement("ds", "KeyInfo", Saml20Constants.Xmldsig);
            elem.AppendChild((doc.CreateElement("lalala")));

            subjectConfirmation.SubjectConfirmationData.AnyElements = new XmlElement[] { elem };

            Saml20SubjectConfirmationValidator validator = new Saml20SubjectConfirmationValidator();
            validator.ValidateSubjectConfirmation(subjectConfirmation);
        }
        #endregion

        #region Utility methods

        private static void CreateSaml20Token(Assertion saml20Assertion)
        {
            XmlDocument doc = AssertionUtil.ConvertAssertionToXml(saml20Assertion);
            new Saml20Assertion(doc.DocumentElement, null, false);
        }

        #endregion


    }
}