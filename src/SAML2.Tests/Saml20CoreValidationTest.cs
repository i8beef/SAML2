using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.Serialization;
using SAML2;
using SAML2.Config;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Schema.XEnc;
using SAML2.Schema.XmlDSig;
using SAML2.Utils;
using SAML2.Validation;
using NUnit.Framework;
using Action = SAML2.Schema.Core.Action;
using Assertion=SAML2.Schema.Core.Assertion;

namespace SAML2.Tests.Saml20
{
    ///<summary>
    /// Tests Saml20 core validation 
    ///</summary>
    [TestFixture]
    public class Saml20CoreValidationTest
    {
        #region Core elements processing rules where a full-blown assertion is not needed

        [Test]
        public void _0000_UTCFromStringTest()
        {
            DateTime now = DateTime.UtcNow;
            string localtime = now.ToString();
            try
            {
                Saml20Utils.FromUTCString(localtime);
                Assert.Fail("Conversion from non-UTC string must not succeed");
            }
            catch (Saml20FormatException)
            {
            }

            // If correctly formatted, conversion must succeed
            Saml20Utils.FromUTCString(now.ToString("o"));

            // If created by the utils class itself, string must be valid
            Saml20Utils.FromUTCString(Saml20Utils.ToUTCString(now));
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Email Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0001_NameID_Invalid_EmptyEmail()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Email;
            nameID.Value = " ";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        /// <summary>
        /// Tests various invalid email addresses. The validation uses the .NET class MailAddress for validation
        /// which explains the large number of tested addresses
        /// </summary>
        [Test]
        public void _0001_NameID_Invalid_Email()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Email;
            Saml20NameIDValidator validator = new Saml20NameIDValidator();

            string[] invalidEmails =
                new string[]
                    {
                        "thisisnotavalid.email@ ", 
                        "thisisnotavalidemail", 
                        "thisisnotavalidemail.com", 
                        "@thisisnotavalidemail.com", 
                        " @thisisnotavalidemail.com", 
                        "@ @thisisnotavalidemail.com", 
                        " @ @thisisnotavalidemail.com", 
                        " . @thisisnotavalidemail.com", 
                        @"\. @thisisnotavalidemail.com", 
                        @"\.\@thisisnotavalidemail.com", 
                        @"a.\@thisisnotavalidemail.com", 
                        @"<.>@thisisnotavalidemail.com", 
                        @"<.a@thisisnotavalidemail.com", 
                        "thisisnotavalid.email@", 
                        "thisisnotavalid.email@ @", 
                        "thisisnotavalid.email@ @ ", 
                    };

            foreach (string email in invalidEmails)
            {
                nameID.Value = email;

                try
                {
                    validator.ValidateNameID(nameID);
                    Assert.Fail("Email address " + email + " is not supposed to be valid");
                }
                catch (Saml20FormatException sfe)
                {
                    Assert.AreEqual(sfe.Message, "Value of NameID is not a valid email address according to the IETF RFC 2822 specification");
                }
            }
        }
        
        [Test]
        public void _0001_NameID_Valid_Email()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Email;
            nameID.Value = "my.address@yours.com";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with X509SubjectName Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_EmptyX509SubjecName()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.X509SubjectName;
            nameID.Value = "";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with X509SubjectName Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_X509SubjecName()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.X509SubjectName;
            nameID.Value = " ";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Windows Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_WindowsDomainQualifiedName_Whitespace()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Windows;
            nameID.Value = " ";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        public void _0002_NameID_Valid_WindowsDomainQualifiedName()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Windows;
            Saml20NameIDValidator validator = new Saml20NameIDValidator();

            nameID.Value = "a";
            validator.ValidateNameID(nameID);

            nameID.Value = "b\a";
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Kerberos Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_KerberosEmpty()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Kerberos;
            nameID.Value = "";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Kerberos Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_Kerberos()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Kerberos;
            nameID.Value = " ";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Kerberos Format attribute MUST contain a Value with at least 3 characters")]
        public void _0002_NameID_Invalid_ContentKerberos1()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Kerberos;
            nameID.Value = @"b";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Kerberos Format attribute MUST contain a Value that contains a '@'")]
        public void _0002_NameID_Invalid_ContentKerberos2()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Kerberos;
            nameID.Value = @"a\b";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        public void _0002_NameID_Valid_Kerberos()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Kerberos;
            nameID.Value = "a@b";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Entity Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_Entity_Empty()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = "";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Entity Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_Entity()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = " ";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Entity Format attribute MUST have a Value that contains no more than 1024 characters")]
        public void _0002_NameID_Invalid_Entity_Length()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = new string('f', 1025);
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        public void _0002_NameID_Valid_Entity()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = new string('f', 1024);
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Entity Format attribute MUST NOT set the NameQualifier attribute")]
        public void _0002_NameID_Invalid_Entity_NameQualifier()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = new string('f', 1024);
            nameID.NameQualifier = "ksljdf";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Entity Format attribute MUST NOT set the SPNameQualifier attribute")]
        public void _0002_NameID_Invalid_Entity_SPNameQualifier()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = new string('f', 1024);
            nameID.SPNameQualifier = "ksljdf";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Entity Format attribute MUST NOT set the SPProvidedID attribute")]
        public void _0002_NameID_Invalid_Entity_SPProvidedID()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Entity;
            nameID.Value = new string('f', 1024);
            nameID.SPProvidedID = "ksljdf";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Persistent Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_Persistent_Empty()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Persistent;
            nameID.Value = "";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Persistent Format attribute MUST contain a Value that contains more than whitespace characters")]
        public void _0002_NameID_Invalid_Persistent()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Persistent;
            nameID.Value = " ";
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Persistent Format attribute MUST have a Value that contains no more than 256 characters")]
        public void _0002_NameID_Invalid_Persistent_Length()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Persistent;
            nameID.Value = new string('f', 257);
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        public void _0002_NameID_Valid_Persistent()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Persistent;
            nameID.Value = new string('f', 256);
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Transient Format attribute MUST have a Value with at least 16 characters (the equivalent of 128 bits)")]
        public void _0002_NameID_Invalid_Transient_MinLength()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Transient;
            nameID.Value = new string('f', 15);
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID with Transient Format attribute MUST have a Value that contains no more than 256 characters")]
        public void _0002_NameID_Invalid_Transient_MaxLength()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Transient;
            nameID.Value = new string('f', 257);
            Saml20NameIDValidator validator = new Saml20NameIDValidator();
            validator.ValidateNameID(nameID);
        }

        [Test]
        public void _0002_NameID_Valid_Transient()
        {
            NameID nameID = new NameID();
            nameID.Format = Saml20Constants.NameIdentifierFormats.Transient;
            Saml20NameIDValidator validator = new Saml20NameIDValidator();

            nameID.Value = new string('f', 256);
            validator.ValidateNameID(nameID);

            nameID.Value = new string('f', 16);
            validator.ValidateNameID(nameID);
        }
        #endregion

        #region Basic assertion tests

        /// <summary>
        /// Make sure that the starting point for all of the tests is valid
        /// </summary>
        [Test]
        public void _0100_BasicAssertionValid()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            new XmlSerializer(typeof(Assertion));

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests validation of wrong version attribute
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Wrong value of version attribute on Assertion element")]
        public void WrongVersion()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Version = "60";

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests validation of missing ID attribute
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Assertion element must have the ID attribute set.")]
        public void MissingID()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.ID = null;

            CreateSaml20Token(saml20Assertion);
        }

        //
        /// <summary>
        /// Tests validation of Issuer Element presence
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Assertion element must have an issuer element.")]
        public void Issuer()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Issuer = null;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests validation of Issuer Element format
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "NameID element has Format attribute which is not a wellformed absolute uri.")]
        public void IssuerFormat()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Issuer.Format = "a non wellformed uri";

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests validation of required IssueInstant Element 
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Assertion element must have the IssueInstant attribute set.")]
        public void IssueInstant()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.IssueInstant = null;

            CreateSaml20Token(saml20Assertion);
        }

        #endregion

        #region Conditions tests

        /// <summary>
        /// Tests the validation that ensures at most 1 OneTimeUse condition
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Assertion contained more than one condition of type OneTimeUse")]
        public void OneTimeUse()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            List<ConditionAbstract> conditions = new List<ConditionAbstract>();

            conditions.Add(new OneTimeUse());
            conditions.Add(new OneTimeUse());
            conditions.AddRange(saml20Assertion.Conditions.Items);

            saml20Assertion.Conditions.Items = conditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests the validation that ensures at most 1 ProxyRestriction condition
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Assertion contained more than one condition of type ProxyRestriction")]
        public void ProxyRestriction()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            List<ConditionAbstract> conditions = new List<ConditionAbstract>();

            conditions.Add(new ProxyRestriction());
            conditions.Add(new ProxyRestriction());
            conditions.AddRange(saml20Assertion.Conditions.Items);

            saml20Assertion.Conditions.Items = conditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests the validation that ensures the Count property tp be a non-negative integer
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Count attribute of ProxyRestriction MUST BE a non-negative integer")]
        public void ProxyRestriction_Invalid_Count()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            List<ConditionAbstract> conditions = new List<ConditionAbstract>();
            ProxyRestriction proxyRestriction = new ProxyRestriction();
            proxyRestriction.Count = "-1";
            conditions.Add(proxyRestriction);

            conditions.AddRange(saml20Assertion.Conditions.Items);
            saml20Assertion.Conditions.Items = conditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests the validity of an assertion that contains a non-negative Count property
        /// </summary>
        [Test]
        public void ProxyRestriction_Valid_Count()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            List<ConditionAbstract> conditions = new List<ConditionAbstract>();
            ProxyRestriction proxyRestriction = new ProxyRestriction();
            proxyRestriction.Count = "1";
            conditions.Add(proxyRestriction);

            conditions.AddRange(saml20Assertion.Conditions.Items);
            saml20Assertion.Conditions.Items = conditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests the validation that ensures the Count property tp be a non-negative integer
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "ProxyRestriction Audience MUST BE a wellformed uri")]
        public void ProxyRestriction_Invalid_Audience()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            List<ConditionAbstract> conditions = new List<ConditionAbstract>();
            ProxyRestriction proxyRestriction = new ProxyRestriction();
            proxyRestriction.Audience = new string[] {"urn:a.wellformed:uri", "http://another/wellformed/uri", "a malformed uri"};
            conditions.Add(proxyRestriction);

            conditions.AddRange(saml20Assertion.Conditions.Items);
            saml20Assertion.Conditions.Items = conditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests the validation that ensures the Count property tp be a non-negative integer
        /// </summary>
        [Test]
        public void ProxyRestriction_Valid_Audience()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            List<ConditionAbstract> conditions = new List<ConditionAbstract>();
            ProxyRestriction proxyRestriction = new ProxyRestriction();
            proxyRestriction.Audience = new string[] { "urn:a.wellformed:uri", "http://another/wellformed/uri"};
            conditions.Add(proxyRestriction);

            conditions.AddRange(saml20Assertion.Conditions.Items);
            saml20Assertion.Conditions.Items = conditions;

            CreateSaml20Token(saml20Assertion);
        }


        /// <summary>
        /// Test validity of assertion when condition is not time restricted
        /// </summary>
        [Test]
        public void TimeRestriction_None()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Conditions.NotBefore = null;
            saml20Assertion.Conditions.NotOnOrAfter = null;
            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test validity of assertion when condition has a valid NotBefore time restriction
        /// </summary>
        [Test]
        public void TimeRestriction_NotBefore_Valid_Yesterday()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            // Test with NotBefore that pre-dates now 
            saml20Assertion.Conditions.NotBefore = DateTime.UtcNow.AddDays(-1);
            saml20Assertion.Conditions.NotOnOrAfter = null;
            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test validity of assertion when condition has a valid NotBefore time restriction
        /// </summary>
        [Test]
        public void TimeRestriction_NotBefore_Valid_Now()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            // Test with NotBefore that pre-dates now 
            saml20Assertion.Conditions.NotBefore = DateTime.UtcNow;
            saml20Assertion.Conditions.NotOnOrAfter = null;
            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test validity of assertion when condition has an invalid NotBefore time restriction
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Conditions.NotBefore must not be in the future")]
        public void TimeRestriction_NotBefore_Invalid()
        {
            // Test with NotBefore that post-dates now 
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Conditions.NotBefore = DateTime.Now.AddDays(1);
            saml20Assertion.Conditions.NotOnOrAfter = null;

            Saml20AssertionValidator validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);
            validator.ValidateTimeRestrictions(saml20Assertion, new TimeSpan());
        }

        /// <summary>
        /// Test validity of assertion when condition has a valid NotOnOrAfter time restriction
        /// </summary>
        [Test]
        public void TimeRestriction_NotOnOrAfter_Valid_Tomorrow()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            // Test with NotOnOrAfter that post-dates now 
            saml20Assertion.Conditions.NotBefore = null;
            saml20Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(1);
            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test validity of assertion when condition has an invalid NotOnOrAfter time restriction
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Conditions.NotOnOrAfter must not be in the past")]
        public void TimeRestriction_NotOnOrAfter_Invalid_Yesterday()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            // Test with NotOnOrAfter that pre-dates now 
            saml20Assertion.Conditions.NotBefore = null;
            saml20Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(-1);

            Saml20AssertionValidator validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);
            validator.ValidateTimeRestrictions(saml20Assertion, new TimeSpan());
        }

        /// <summary>
        /// Test validity of assertion when condition has an invalid NotOnOrAfter time restriction
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Conditions.NotOnOrAfter must not be in the past")]
        public void TimeRestriction_NotOnOrAfter_Invalid_Now()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            // Test with NotOnOrAfter that pre-dates now 
            saml20Assertion.Conditions.NotBefore = null;
            saml20Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow;

            Saml20AssertionValidator validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);
            validator.ValidateTimeRestrictions(saml20Assertion, new TimeSpan());
        }

        /// <summary>
        /// Test validity of assertion when condition is time restricted in both directions
        /// </summary>
        [Test]
        public void TimeRestriction_Both()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            saml20Assertion.Conditions.NotBefore = DateTime.UtcNow.AddDays(-1);
            saml20Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(1);
            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that services that are not configured with abny allowed audience URI's do not 
        /// consider audience-restricted assertions valid
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "The service is not configured to meet any audience restrictions")]
        public void AudienceRestriction_Invalid_NoConfiguration()
        {
            var sp = Saml2Config.GetConfig();
            var origAllowedAudiences = new AllowedAudienceUriCollection();
            origAllowedAudiences.AddRange(sp.AllowedAudienceUris.Select(x => new AudienceUriElement {Uri = x.Uri}));

            try
            {
                sp.AllowedAudienceUris = null;

                Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
                CreateSaml20Token(saml20Assertion);
            }
            finally
            {
                sp.AllowedAudienceUris = origAllowedAudiences;
            }
        }

        /// <summary>
        /// Test that services that are not configured with the right allowed audience URI's do not 
        /// consider audience-restricted assertions valid
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "The service is not configured to meet the given audience restrictions")]
        public void AudienceRestriction_Invalid_ConfigurationSetup()
        {
            var sp = Saml2Config.GetConfig();
            var origAllowedAudiences = new AllowedAudienceUriCollection();
            origAllowedAudiences.AddRange(sp.AllowedAudienceUris.Select(x => new AudienceUriElement { Uri = x.Uri }));

            try
            {
                sp.AllowedAudienceUris = new AllowedAudienceUriCollection();
                sp.AllowedAudienceUris.Add(new AudienceUriElement { Uri = "urn:lalal" });

                Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
                CreateSaml20Token(saml20Assertion);
            }
            finally
            {
                sp.AllowedAudienceUris = origAllowedAudiences;
            }
        }

        /// <summary>
        /// Test that audience-restricted assertions are not valid if the restriction values are incorrectly formatted
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Audience element has value which is not a wellformed absolute uri")]
        public void AudienceRestriction_Invalid_Assertion()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            AudienceRestriction sar = new AudienceRestriction();
            sar.Audience = new List<string>( new string[] { "malformed uri" });

            saml20Assertion.Conditions.Items = new List<ConditionAbstract>(new ConditionAbstract[] { sar });
            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that audience-restricted assertions are not valid if ANY of the audience restrictions is not met 
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "The service is not configured to meet the given audience restrictions")]
        public void AudienceRestriction_Invalid_MultipleAudienceRestrictions()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<ConditionAbstract> audienceConditions = new List<ConditionAbstract>(saml20Assertion.Conditions.Items);

            AudienceRestriction sar = new AudienceRestriction();
            sar.Audience = new List<string>(new string[] { "http://well/formed.uri" });
            audienceConditions.Add(sar);

            saml20Assertion.Conditions.Items = audienceConditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that audience-restricted assertions are valid if ALL of the audience restrictions are met 
        /// </summary>
        [Test]
        public void AudienceRestriction_Valid_MultipleAudienceRestrictions()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<ConditionAbstract> audienceConditions = new List<ConditionAbstract>(saml20Assertion.Conditions.Items);

            AudienceRestriction sar = new AudienceRestriction();
            sar.Audience = new List<string>(new string[] { "urn:borger.dk:id" });
            audienceConditions.Add(sar);

            saml20Assertion.Conditions.Items = audienceConditions;

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that audience-restricted assertions are valid if ANY of the audiences within a single audience
        /// restrictions is met
        /// </summary>
        [Test]
        public void AudienceRestriction_Valid_SeveralAudiences()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            foreach (ConditionAbstract sca in saml20Assertion.Conditions.Items)
            {
                if (!(sca is AudienceRestriction))
                    continue;

                AudienceRestriction sar = (AudienceRestriction)sca;
                List<string> audiences = new List<string>(sar.Audience);
                audiences.Add("http://well/formed.uri");
                sar.Audience = audiences;
                break;
            }

            CreateSaml20Token(saml20Assertion);
        }

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
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST have at least one " + KeyInfo.ELEMENT_NAME + " subelement")]
        public void SubjectConfirmationData_Invalid_KeyInfoConfirmationData_NoAnyElement()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST contain at least one " + KeyInfo.ELEMENT_NAME + " in namespace " + Saml20Constants.XMLDSIG)]
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
            subjectConfirmationData.AnyElements = new XmlElement[] { doc.CreateElement("ds", "KeyInfo", Saml20Constants.XMLDSIG) };

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST contain at least one " + KeyInfo.ELEMENT_NAME + " in namespace " + Saml20Constants.XMLDSIG)]
        public void SubjectConfirmationData_Invalid_KeyInfoConfirmationData_WrongAnyElement()
        {
            KeyInfoConfirmationData subjectConfirmationData = new KeyInfoConfirmationData();
            subjectConfirmationData.Recipient = "urn:wellformed.uri:ok";
            XmlDocument doc = new XmlDocument();
            XmlElement elem = doc.CreateElement("ds", "KeyInfo", "http://wrongNameSpace.uri");
            elem.AppendChild((doc.CreateElement("ds", "KeyName", Saml20Constants.XMLDSIG)));

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
            XmlElement elem = doc.CreateElement("ds", "KeyInfo", Saml20Constants.XMLDSIG);
            elem.AppendChild((doc.CreateElement("lalala")));

            subjectConfirmationData.AnyElements = new XmlElement[] { elem };

            Saml20SubjectConfirmationDataValidator validator = new Saml20SubjectConfirmationDataValidator();
            validator.ValidateSubjectConfirmationData(subjectConfirmationData);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "SubjectConfirmationData element MUST have at least one " + KeyInfo.ELEMENT_NAME + " subelement")]
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
            XmlElement elem = doc.CreateElement("ds", "KeyInfo", Saml20Constants.XMLDSIG);
            elem.AppendChild((doc.CreateElement("lalala")));

            subjectConfirmation.SubjectConfirmationData.AnyElements = new XmlElement[] { elem };

            Saml20SubjectConfirmationValidator validator = new Saml20SubjectConfirmationValidator();
            validator.ValidateSubjectConfirmation(subjectConfirmation);
        }
        #endregion

        #region Statements tests

        /// <summary>
        /// Tests that AuthnStatement objects must have an AuthnInstant attribute
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnStatement MUST have an AuthnInstant attribute")]
        public void AuthnStatement_Invalid_AuthnInstant()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            statements.Add(new AuthnStatement());

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have an AuthnInstant attribute
        /// </summary>
        [Ignore]    // TODO: test data needs fixing
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnStatement attribute SessionNotOnOrAfter MUST be in the future")]
        public void AuthnStatement_Invalid_SessionNotOnOrAfter()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(-1);
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            Saml20AssertionValidator validator = new Saml20AssertionValidator(AssertionUtil.GetAudiences(), false);
            validator.ValidateTimeRestrictions(saml20Assertion, new TimeSpan(0, 0, 0));
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have an AuthnContext element
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnStatement MUST have an AuthnContext element")]
        public void AuthnStatement_Invalid_AuthnContextNull()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have non-null contents
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContext element MUST contain at least one AuthnContextClassRef, AuthnContextDecl or AuthnContextDeclRef element")]
        public void AuthnStatement_Invalid_AuthnContextNoContextItems()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have non-empty contents
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContext element MUST contain at least one AuthnContextClassRef, AuthnContextDecl or AuthnContextDeclRef element")]
        public void AuthnStatement_Invalid_AuthnContextEmpty()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new List<object>().ToArray();
            sas.AuthnContext.ItemsElementName = new List<ItemsChoiceType5>().ToArray();
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have a AuthnContextClassRef type as the first element if it is present
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContextClassRef must be in the first element")]
        public void AuthnStatement_Invalid_AuthnContextClassRef_MustBeFirst()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new object[] { "urn:a.valid.uri:string", "urn:a.valid.uri:string" };
            sas.AuthnContext.ItemsElementName = new ItemsChoiceType5[] { ItemsChoiceType5.AuthnContextDeclRef, ItemsChoiceType5.AuthnContextClassRef };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have no more than 2 {AuthnContextClassRef, AuthnContextDeclRef} elements
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContext MUST NOT contain more than two elements.")]
        public void AuthnStatement_Invalid_AuthnContext_Max2Refs()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new object[3] { "urn:a.valid.uri:string", "urn:a.valid.uri:string", "urn:a.valid.uri:string" };
            sas.AuthnContext.ItemsElementName = new ItemsChoiceType5[3] { ItemsChoiceType5.AuthnContextDeclRef, ItemsChoiceType5.AuthnContextDeclRef, ItemsChoiceType5.AuthnContextDeclRef };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }


        /// <summary>
        /// Tests that AuthnStatement objects must have an valid uri content for AuthnContextClassRef types
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContextClassRef has a value which is not a wellformed absolute uri")]
        public void AuthnStatement_Invalid_AuthnContextClassRefUri()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new object[2] { String.Empty, "urn:a.valid.uri:string"};
            sas.AuthnContext.ItemsElementName = new ItemsChoiceType5[2] { ItemsChoiceType5.AuthnContextClassRef, ItemsChoiceType5.AuthnContextDeclRef };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have an valid uri content for AuthnContextDeclRef types
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContextDeclRef has a value which is not a wellformed absolute uri")]
        public void AuthnStatement_Invalid_AuthnContextDeclRefUri()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new object[2] { "urn:a.valid.uri:string", "an/invalid/uri/string.aspx" };
            sas.AuthnContext.ItemsElementName = new ItemsChoiceType5[2] { ItemsChoiceType5.AuthnContextClassRef, ItemsChoiceType5.AuthnContextDeclRef };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects MUST NOT have content of type AuthnContextDecl
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthnContextDecl elements are not allowed in this implementation")]
        public void AuthnStatement_Invalid_AuthnContextDecl()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new object[1] { new AuthnStatement() };
            sas.AuthnContext.ItemsElementName = new ItemsChoiceType5[1] { ItemsChoiceType5.AuthnContextDecl };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Tests that AuthnStatement objects must have an valid uri content for AuthenticatingAuthority entries
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AuthenticatingAuthority array contains a value which is not a wellformed absolute uri")]
        public void AuthnStatement_Invalid_AuthnContextAuthenticatingAuthorityUri()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AuthnStatement sas = new AuthnStatement();
            sas.AuthnInstant = DateTime.UtcNow;
            sas.SessionNotOnOrAfter = DateTime.UtcNow.AddHours(1);
            sas.AuthnContext = new AuthnContext();
            sas.AuthnContext.Items = new object[2] { "urn:a:valid.uri:string", "http://another/valid/uri.string" };
            sas.AuthnContext.ItemsElementName = new ItemsChoiceType5[2] { ItemsChoiceType5.AuthnContextClassRef, ItemsChoiceType5.AuthnContextDeclRef };
            sas.AuthnContext.AuthenticatingAuthority = new string[2] { "urn:aksdlfj", "urn/invalid" };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that AttributeStatement objects must have a non-null Items-list
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AttributeStatement MUST contain at least one Attribute or EncryptedAttribute")]
        public void AttributeStatement_Invalid_NoAttributes()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas = new AttributeStatement();
            sas.Items = null;
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that AttributeStatement objects must have a non-empty Items-list
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "AttributeStatement MUST contain at least one Attribute or EncryptedAttribute")]
        public void AttributeStatement_Invalid_EmptyAttributes()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas = new AttributeStatement();
            sas.Items = new object[0];
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that Attribute objects must have a non-empty Name
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Name attribute of Attribute element MUST contain at least one non-whitespace character")]
        public void AttributeStatement_Invalid_Attribute()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas = new AttributeStatement();
            sas.Items = new object[1] { new SamlAttribute() };
            statements.Add(sas);

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that xml attribute extensions on Attribute objects must be namespace qualified
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Attribute extension xml attributes MUST BE namespace qualified")]
        public void AttributeStatement_Invalid_Attribute_AnyAttrUnqualified()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas =
                (AttributeStatement)statements.Find(delegate(StatementAbstract ssa) { return ssa is AttributeStatement; });
            SamlAttribute sab = (SamlAttribute)sas.Items[0];
            XmlDocument doc = new XmlDocument();
            sab.AnyAttr = new XmlAttribute[1] { doc.CreateAttribute(String.Empty, "Nonqualified", String.Empty) };

            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that xml attribute extensions on Attribute objects must be namespace qualified
        /// </summary>
        [Test]
        public void AttributeStatement_Invalid_Attribute_AnyAttrSamlQualified()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas =
                (AttributeStatement)statements.Find(delegate(StatementAbstract ssa) { return ssa is AttributeStatement; });
            SamlAttribute sab = (SamlAttribute)sas.Items[0];
            XmlDocument doc = new XmlDocument();
            saml20Assertion.Items = statements.ToArray();

            foreach (string samlns in Saml20Constants.SAML_NAMESPACES)
            {
                sab.AnyAttr = new XmlAttribute[1] { doc.CreateAttribute("someprefix", "SamlQualified", samlns) };

                try
                {
                    CreateSaml20Token(saml20Assertion);
                    Assert.Fail("A SAML-qualified xml attribute extension on Attribute must not be valid");
                }
                catch (Saml20FormatException sfe)
                {
                    Assert.AreEqual(sfe.Message, "Attribute extension xml attributes MUST NOT use a namespace reserved by SAML");
                }
            }
        }

        /// <summary>
        /// Test that EncryptedAttribute objects must have an EncryptedData child element
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "An EncryptedAttribute MUST contain an xenc:EncryptedData element")]
        public void AttributeStatement_Invalid_EncryptedAttribute_NoData()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas =
                (AttributeStatement)statements.Find(delegate(StatementAbstract ssa) { return ssa is AttributeStatement; });
            List<object> attributes = new List<object>(sas.Items);
            EncryptedElement ee = new EncryptedElement();
            attributes.Add(ee);
            sas.Items = attributes.ToArray();
            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        /// <summary>
        /// Test that EncryptedData element must have the correct Type value
        /// </summary>
        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Type attribute of EncryptedData MUST have value " + Saml20Constants.XENC + "Element" + " if it is present")]
        public void AttributeStatement_Invalid_EncryptedAttribute_WrongType()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas =
                (AttributeStatement)statements.Find(delegate(StatementAbstract ssa) { return ssa is AttributeStatement; });
            List<object> attributes = new List<object>(sas.Items);
            EncryptedElement ee = new EncryptedElement();
            ee.encryptedData = new EncryptedData();
            ee.encryptedData.Type = "SomeWrongType";
            attributes.Add(ee);
            sas.Items = attributes.ToArray();
            saml20Assertion.Items = statements.ToArray();

            CreateSaml20Token(saml20Assertion);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Resource attribute of AuthzDecisionStatement is REQUIRED")]
        public void AuthzDecisionStatement_Invalid_Resource()
        {
            AuthzDecisionStatement statement = new AuthzDecisionStatement();
            Saml20StatementValidator validator = new Saml20StatementValidator();

            statement.Resource = null;
            validator.ValidateStatement(statement);
        }

        [Test]
        [ExpectedException(typeof(Saml20FormatException), ExpectedMessage = "Resource attribute of AuthzDecisionStatement has a value which is not a wellformed absolute uri")]
        public void AuthzDecisionStatement_Invalid_MalformedResource()
        {
            AuthzDecisionStatement statement = new AuthzDecisionStatement();
            Saml20StatementValidator validator = new Saml20StatementValidator();

            statement.Resource = "a malformed uri";
            validator.ValidateStatement(statement);
        }

        [Test]
        public void AuthzDecisionStatement_Valid_Resources()
        {
            AuthzDecisionStatement statement = new AuthzDecisionStatement();
            Saml20StatementValidator validator = new Saml20StatementValidator();

            statement.Resource = String.Empty;
            Action action = new Action();
            action.Namespace = "http://valid/namespace";
            statement.Action = new Action[] { action };
            validator.ValidateStatement(statement);

            statement.Resource = "urn:valid.ok:askjld";
            validator.ValidateStatement(statement);
        }

        #endregion

        #region Utility methods

        private static void CreateSaml20Token(Assertion saml20Assertion)
        {
            XmlDocument doc = AssertionUtil.ConvertAssertion(saml20Assertion);
            new Saml20Assertion(doc.DocumentElement, null, false);
        }

        #endregion


    }
}