using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using SAML2.Schema.Metadata;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using NUnit.Framework;
using SAML2.Config;
using SAML2;
using SAML2.Protocol;
using Assertion=SAML2.Schema.Core.Assertion;
using Saml20Assertion=SAML2.Saml20Assertion;

namespace dk.nita.test.Saml20
{
    /// <summary>
    /// Unit tests related to the handling and functionality of encrypted assertions.
    /// </summary>
    [TestFixture]
    public class EncryptedAssertionTest
    {    
        private static Saml20Assertion CreateDKSaml20TokenFromAssertion(Saml20EncryptedAssertion encAss)
        {
            return new Saml20Assertion(encAss.Assertion.DocumentElement, null, false);
        }

        [Test]
        [ExpectedException(typeof(Saml20Exception), ExpectedMessage = "Assertion is no longer valid.")]
        public void DecryptFOBSAssertion_01()
        {
            DecryptFOBSAssertion(@"Assertions\fobs-assertion2");
        }

        /// <summary>
        /// Decrypts an assertion we received from "fælles-offentlige brugerstyring".
        /// </summary>        
        private static void DecryptFOBSAssertion(string file)
        {
            string assertionBase64 = File.ReadAllText(file);
            byte[] assertionBytes = Convert.FromBase64String(assertionBase64);

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load( new MemoryStream(assertionBytes) );

            XmlNodeList encryptedList =
                doc.GetElementsByTagName(EncryptedAssertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            Assert.That(encryptedList.Count == 1);

            // Do some mock configuration.
            FederationConfig config = FederationConfig.GetConfig();
            config.AllowedAudienceUris.Audiences.Add("https://saml.safewhere.net");

            SAML20FederationConfig descr = ConfigurationReader.GetConfig<SAML20FederationConfig>();
            descr.Endpoints.metadataLocation = @"Protocol\MetadataDocs\FOBS"; // Set it manually.     
            Assert.That(Directory.Exists(descr.Endpoints.metadataLocation));
            descr.Endpoints.Refresh();

            X509Certificate2 cert = new X509Certificate2(@"Certificates\SafewhereTest_SFS.pfx", "test1234");
            Saml20EncryptedAssertion encass = 
                new Saml20EncryptedAssertion((RSA) cert.PrivateKey);

            encass.LoadXml((XmlElement) encryptedList[0]);
            encass.Decrypt();

            // Retrieve metadata                       
            Saml20Assertion assertion = new Saml20Assertion(encass.Assertion.DocumentElement, null, false);

            IDPEndPoint endp = descr.FindEndPoint(assertion.Issuer);
            Assert.IsNotNull(endp, "Endpoint not found");
            Assert.IsNotNull(endp.metadata, "Metadata not found");

            try
            {
                assertion.CheckValid(AssertionUtil.GetTrustedSigners(assertion.Issuer));
                Assert.Fail("Verification should fail. Token does not include its signing key.");
            } catch(InvalidOperationException)
            {}

            Assert.IsNull(assertion.SigningKey, "Signing key is already present on assertion. Modify test.");
            Assert.That(assertion.CheckSignature(Saml20SignonHandler.GetTrustedSigners(endp.metadata.GetKeys(KeyTypes.signing), endp)));
            Assert.IsNotNull(assertion.SigningKey, "Signing key was not set on assertion instance.");             
        }

        /// <summary>
        /// Loads an encrypted assertion, retrieves the symmetric key used for its encryption and decrypts it.
        /// </summary>
        [Test]
        public void DecryptAssertion_01()
        {
            DecryptAssertion(@"Assertions\EncryptedAssertion_01");
        }

        /// <summary>
        /// An example on how to decrypt an encrypted assertion.
        /// </summary>
        private static void DecryptAssertion(string file)
        {            
            XmlDocument doc = new XmlDocument();
            doc.Load(file);            
            XmlElement encryptedDataElement = GetElement(SAML2.Schema.XEnc.EncryptedData.ELEMENT_NAME, Saml20Constants.XENC, doc);                        

            
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.LoadXml(encryptedDataElement);

            XmlNodeList nodelist = doc.GetElementsByTagName(SAML2.Schema.XmlDSig.KeyInfo.ELEMENT_NAME, Saml20Constants.XMLDSIG);
            Assert.That(nodelist.Count > 0);

            KeyInfo key = new KeyInfo();
            key.LoadXml((XmlElement) nodelist[0]);

            // Review: Is it possible to figure out which certificate to load based on the Token?
            /*
             * Comment:
             * It would be possible to provide a key/certificate identifier in the EncryptedKey element, which contains the "recipient" attribute.
             * The implementation (Safewhere.Tokens.Saml20.Saml20EncryptedAssertion) currently just expects an appropriate asymmetric key to be provided,
             * and is not not concerned about its origin. 
             * If the need arises, we can easily extend the Saml20EncryptedAssertion class with a property that allows extraction key info, eg. the "recipient" 
             * attribute.
             */
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

            // ms-help://MS.MSDNQTR.v80.en/MS.MSDN.v80/MS.NETDEVFX.v20.en/CPref18/html/T_System_Security_Cryptography_Xml_KeyInfoClause_DerivedTypes.htm
            // Look through the list of KeyInfo elements to find the encrypted key.
            SymmetricAlgorithm symmetricKey = null;
            foreach (KeyInfoClause keyInfoClause in key)
            {
                if (keyInfoClause is KeyInfoEncryptedKey)
                {
                    KeyInfoEncryptedKey keyInfoEncryptedKey = (KeyInfoEncryptedKey) keyInfoClause;
                    EncryptedKey encryptedKey = keyInfoEncryptedKey.EncryptedKey;
                    symmetricKey = new RijndaelManaged();
                                        
                    symmetricKey.Key =
                        EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, (RSA) cert.PrivateKey, false);
                    continue;
                }
            }
            // Explode if we didn't manage to find a viable key.
            Assert.IsNotNull(symmetricKey);
            EncryptedXml encryptedXml = new EncryptedXml();
            byte[] plaintext = encryptedXml.DecryptData(encryptedData, symmetricKey);

            XmlDocument assertion = new XmlDocument();
            assertion.Load(new StringReader(System.Text.Encoding.UTF8.GetString(plaintext)));

            // A very simple test to ensure that there is indeed an assertion in the plaintext.
            Assert.AreEqual(Assertion.ELEMENT_NAME, assertion.DocumentElement.LocalName);
            Assert.AreEqual(Saml20Constants.ASSERTION, assertion.DocumentElement.NamespaceURI);
        }

        /// <summary>
        /// Generates an encrypted assertion and writes it to disk. 
        /// </summary>
        [Test]
        public void GenerateEncryptedAssertion_01()
        {
            XmlDocument assertion = AssertionUtil.GetTestAssertion_01();

            // Create an EncryptedData instance to hold the results of the encryption.o
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.Type = EncryptedXml.XmlEncElementUrl;
            encryptedData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Create a symmetric key. 
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 256;
            aes.GenerateKey();

            // Encrypt the assertion and add it to the encryptedData instance.
            EncryptedXml encryptedXml = new EncryptedXml();
            byte[] encryptedElement = encryptedXml.EncryptData(assertion.DocumentElement, aes, false);
            encryptedData.CipherData.CipherValue = encryptedElement;

            // Add an encrypted version of the key used.
            encryptedData.KeyInfo = new KeyInfo();

            EncryptedKey encryptedKey = new EncryptedKey();

            // Use this certificate to encrypt the key.
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");
            RSA publicKeyRSA = cert.PublicKey.Key as RSA;
            Assert.IsNotNull(publicKeyRSA, "Public key of certificate was not an RSA key. Modify test.");
            encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
            encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, publicKeyRSA, false));


            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            // Create the resulting Xml-document to hook into.
            EncryptedAssertion encryptedAssertion = new EncryptedAssertion();
            encryptedAssertion.encryptedData = new SAML2.Schema.XEnc.EncryptedData();
            encryptedAssertion.encryptedKey = new SAML2.Schema.XEnc.EncryptedKey[1];
            encryptedAssertion.encryptedKey[0] = new SAML2.Schema.XEnc.EncryptedKey();

            XmlDocument result;
            result = Serialization.Serialize(encryptedAssertion);            

            XmlElement encryptedDataElement = GetElement(SAML2.Schema.XEnc.EncryptedData.ELEMENT_NAME, Saml20Constants.XENC, result);
            EncryptedXml.ReplaceElement(encryptedDataElement, encryptedData, false);
        }        

        /// <summary>
        /// Attempts to decrypt the assertion in the file "EncryptedAssertion_01".
        /// </summary>
        [Test]
        public void TestAssertionDecryption_01()
        {
            // Load the assertion
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(@"Assertions\EncryptedAssertion_01"));

            // Find the transport key.
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion((RSA) cert.PrivateKey, doc);
            Assert.IsNull(encryptedAssertion.Assertion); // Check that it does not contain an assertion prior to decryption.
            encryptedAssertion.Decrypt();
            Assert.IsNotNull(encryptedAssertion.Assertion);
            Saml20Assertion assertion = CreateDKSaml20TokenFromAssertion(encryptedAssertion);
        }


        /// <summary>
        /// Test that the <code>Saml20EncryptedAssertion</code> class is capable of finding keys that are "peer" included,
        /// ie. the &lt;EncryptedKey&gt; element is a sibling of the &lt;EncryptedData&gt; element.
        /// </summary>
        [Test]        
        public void TestAssertionDecryption_02()
        {
            // Load the assertion
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(@"Assertions\EncryptedAssertion_02"));

            // Find the transport key.
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion((RSA)cert.PrivateKey, doc);
            Assert.IsNull(encryptedAssertion.Assertion); // Check that it does not contain an assertion prior to decryption.
            encryptedAssertion.Decrypt();
            Assert.IsNotNull(encryptedAssertion.Assertion);
        }        
        
        /// <summary>
        /// Test that the <code>Saml20EncryptedAssertion</code> class is capable of finding keys that are "peer" included,
        /// ie. the &lt;EncryptedKey&gt; element is a sibling of the &lt;EncryptedData&gt; element.
        /// </summary>
        [Test]        
        public void TestAssertionDecryption_03()
        {
            // Load the assertion
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(@"Assertions\EncryptedAssertion_03"));

            // Find the transport key.
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion((RSA)cert.PrivateKey, doc);
            Assert.IsNull(encryptedAssertion.Assertion); // Check that it does not contain an assertion prior to decryption.
            encryptedAssertion.Decrypt();
            Assert.IsNotNull(encryptedAssertion.Assertion);
        }

        /// <summary>
        /// Test that the <code>Saml20EncryptedAssertion</code> class is capable using 3DES keys for the session key and OAEP-padding for 
        /// the encryption of the session key.
        /// </summary>
        [Test]
        public void TestAssertionDecryption_04()
        {
            // Load the assertion
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(@"Assertions\EncryptedAssertion_04"));

            // Find the transport key.
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion((RSA)cert.PrivateKey, doc);
            Assert.IsNull(encryptedAssertion.Assertion); // Check that it does not contain an assertion prior to decryption.
            encryptedAssertion.Decrypt();
            Assert.IsNotNull(encryptedAssertion.Assertion);
            XmlNodeList list;

            // Perform some rudimentary tests on the output.
            list = encryptedAssertion.Assertion.GetElementsByTagName(Assertion.ELEMENT_NAME, Saml20Constants.ASSERTION);
            Assert.AreEqual(1, list.Count);
        }

        /// <summary>
        /// Test that the <code>Saml20EncryptedAssertion</code> class is capable using 3DES keys for the session key and OAEP-padding for 
        /// the encryption of the session key.
        /// </summary>
        [Test]
        public void TestAssertionDecryption_05()
        {
            // Load the assertion
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(@"Assertions\EncryptedAssertion_05"));

            // Find the transport key.
            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");

            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion((RSA)cert.PrivateKey, doc);
            Assert.IsNull(encryptedAssertion.Assertion); // Check that it does not contain an assertion prior to decryption.
            encryptedAssertion.Decrypt();
            Assert.IsNotNull(encryptedAssertion.Assertion);
            XmlNodeList list;

            // Perform some rudimentary tests on the output.
            list = encryptedAssertion.Assertion.GetElementsByTagName(Assertion.ELEMENT_NAME, Saml20Constants.ASSERTION);
            Assert.AreEqual(1, list.Count);
        }


        /// <summary>
        /// Uses the <code>EncryptedAssertion</code> class to encrypt an assertion. 
        /// </summary>
        [Test]
        public void TestAssertionEncryption()
        {
            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion();
            encryptedAssertion.Assertion = AssertionUtil.GetTestAssertion_01();

            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");
            encryptedAssertion.TransportKey = (RSA) cert.PublicKey.Key;

            encryptedAssertion.Encrypt();

            XmlDocument encryptedAssertionXML = encryptedAssertion.GetXml();
            Assert.IsNotNull(encryptedAssertionXML);

            // A number of simple tests until we get some better way to verify the generated encrypted assertion.
            XmlNodeList list;
            list = encryptedAssertionXML.GetElementsByTagName(EncryptedAssertion.ELEMENT_NAME, Saml20Constants.ASSERTION);
            Assert.AreEqual(1, list.Count);

            list = encryptedAssertionXML.GetElementsByTagName(SAML2.Schema.XEnc.EncryptedKey.ELEMENT_NAME, Saml20Constants.XENC);
            Assert.AreEqual(1, list.Count);
        }

        /// <summary>
        /// Tests that it is possible to specify the algorithm of the session key.
        /// </summary>
        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void TestAlgorithmConfiguration_01()
        {
            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion();
            encryptedAssertion.SessionKeyAlgorithm = "RSA";
            Assert.Fail("\"Saml20EncryptedAssertion\" class does not respond to incorrect algorithm identifying URI.");
        }

        /// <summary>
        /// Tests that it is possible to specify the algorithm of the session key.
        /// Steps: 
        /// - Create a new encrypted assertion with a specific session key algorithm that is different than the default.
        /// - Decrypt the assertion and verify that it uses the correct algorithm.
        /// - Verify that the SessionKeyAlgorithm property behaves as expected.
        /// </summary>
        [Test]
        public void TestAlgorithmConfiguration_02()
        {
            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion();
            encryptedAssertion.SessionKeyAlgorithm = EncryptedXml.XmlEncAES128Url;
            encryptedAssertion.Assertion = AssertionUtil.GetTestAssertion_01();

            X509Certificate2 cert = new X509Certificate2(@"Certificates\sts_dev_certificate.pfx", "test1234");
            encryptedAssertion.TransportKey = (RSA)cert.PublicKey.Key;

            encryptedAssertion.Encrypt();
            XmlDocument encryptedAssertionXML = encryptedAssertion.GetXml();
            Assert.IsNotNull(encryptedAssertionXML);

            // Verify that the EncryptionMethod element is set correctly.
            XmlNodeList list = 
                encryptedAssertionXML.GetElementsByTagName(SAML2.Schema.XEnc.EncryptedData.ELEMENT_NAME,
                                                           Saml20Constants.XENC);
            Assert.AreEqual(1, list.Count);
            XmlElement el = (XmlElement) list[0];

            // Go through the children and look for the EncryptionMethod element, and verify its algorithm attribute.
            bool encryptionMethodFound = false;
            foreach (XmlNode node in el.ChildNodes)
            {
                if (node.LocalName == SAML2.Schema.XEnc.EncryptionMethod.ELEMENT_NAME &&
                    node.NamespaceURI == Saml20Constants.XENC)
                {
                    el = (XmlElement) node;
                    Assert.AreEqual(EncryptedXml.XmlEncAES128Url, el.GetAttribute("Algorithm"));
                    encryptionMethodFound = true;
                }
            }
            Assert.That(encryptionMethodFound, "Unable to find EncryptionMethod element in EncryptedData.");

            // Now decrypt the assertion, and verify that it recognizes the Algorithm used.
            Saml20EncryptedAssertion decrypter = new Saml20EncryptedAssertion((RSA) cert.PrivateKey);
            Assert.IsNull(decrypter.Assertion);
            decrypter.LoadXml(encryptedAssertionXML.DocumentElement);
            // Set a wrong algorithm and make sure that the class gets it algorithm info from the assertion itself.
            decrypter.SessionKeyAlgorithm = EncryptedXml.XmlEncTripleDESUrl;
            decrypter.Decrypt();
            // Verify that the class has discovered the correct algorithm and set the SessionKeyAlgorithm property accordingly.
            Assert.AreEqual(EncryptedXml.XmlEncAES128Url, decrypter.SessionKeyAlgorithm);
            Assert.IsNotNull(decrypter.Assertion);
        }



        private static XmlElement GetElement(string element, string ns, XmlDocument doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(element, ns);
            Assert.That(list.Count == 1);

            return (XmlElement)list[0];
        }
    }
}