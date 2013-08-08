using System;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SAML2.Bindings;
using NUnit.Framework;

namespace SAML2.Tests.Saml20.Protocol
{
    [TestFixture]
    public class HttpRedirectBindingTest
    {
        /// <summary>
        /// Parses an actual redirect URL from Ping.
        /// </summary>
        [Test]
        public void PingTest_01()
        {
            // Actual URL from Ping.
            string s =                
                "http://haiku.safewhere.local/Saml20TestWeb/SSOLogout.saml2.aspx?SAMLResponse=fZFRa8IwEMe%2FSsm7bZq2qMEWZN1DwSEY0eGLpGmqZTUpuYTpt19bGVMYPob7%2FX%2BXu1sAv7QdXemTdnYjodMKpJdLsI3ittEqRWdrOxoEZ958OR94Lb%2FP0ki%2F1YK3AevjBG97fi%2FLgLH13eQPWuJz6K7IK9SveKtT1FQ1qYSoSSRIVMVhPJ3hpMQRj6IwKUVcJn0CwMlCgeXKpohgPJvgaILjbUhoQmg49cl8dui5PEWH%2BoaB6P2arAtlq%2FqWF%2FNTXn8y3yBvJw2MQxAfI%2B96aRXQceIUOaOo5tAAVfwigVpB2fJjRXuSdkZbLXSLssVA0%2FE%2F5iH%2FOs4BpBmWh7JlvnrfHIcKwcciXwQPvru8o8xy6%2BD59aYr6e146%2BTrVjDSlDkhJAAKsnuHP2nw34GzHw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=UoYGLeSCYOSvjIaBpTcgtq2O0Nbz%2BVk%2BaaLESje8%2FZKxGNmWrFXJjSPrA403J23NeQzbxxVgOwSP8idIM95BhlVwxpiG%2B7%2FhJyNNrjGPohmD3cQpBWoWqZ8IEudDc%2FwDCshPb6wTdr6%2FOdKXQ2uwSK5NA2LYI8AAN5sq9kPtVvk%3D";
            Uri url =
                new Uri(s);            

            HttpRedirectBindingParser parser = new HttpRedirectBindingParser(url);

            X509Certificate2 cert = new X509Certificate2(@"Certificates\pingcertificate.crt");
            Assert.That(parser.CheckSignature(cert.PublicKey.Key));
        }

        [Test]
        public void PingTest_02()
        {
            string s =
                "https://adler.safewhere.local:9031/idp/SSO.saml2?SAMLRequest=7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ%2fff%2fz9cZmQBbPbOStrJniGAqsgfP358Hz8iHv8e7xZlepnXTVEtP%2ftod7zz0e9x9Bsnj3%2fR7qPjdTtfvsp%2f0Tpv2vTs6WcfFbP7ew8fPnhw%2f97%2bZC%2fbvzebPty59%2bn92b37kwc755O9g92P0p80kPYIUnrWNOv8bNm02bKlj3Z2DrZ37m3v7L%2fZ3X90b%2ffRvU%2fHDz69v%2fPw3t5PfZQSHsvm0S%2fa%2feyjdb18VGVN0TxaZou8edROH70%2b%2fuL5IwL5aFVXbTWtyo8IyTR9zB3U8u7mF7OmyeuWUPvoCM2%2bnRVv14%2fvyvsC66Razgq0aN4THt6m94%2fXsyJfTvNXRK%2b6mOI7%2fcr70u%2fcfqYA7AddCI%2fvOtwwOXc7s3P0%2fwA%3d&SigAlg=http%3a%2f%2fwww.w3.org%2f2000%2f09%2fxmldsig%23rsa-sha1&Signature=UsZV%2bFga0YfCQaozLomKfV8jyNt85GMIYLFoBA9jrwFfabL%2bpAWVmlhwHyAMv50uxJWFc57v2ySj5Pc6e1t0NyyaguRL8VOKqB4P3svXV5U4iU0Gq4Rp1SJu0bj538%2f01X8IINmcAJMLdrx1cqCoRmofEcPPoQODWhQoq%2brjZdE%3d";
            Uri url = new Uri(s);

            HttpRedirectBindingParser parser = new HttpRedirectBindingParser(url);
            X509Certificate2 cert = new X509Certificate2(@"Certificates\SafewhereTest_SFS.pfx", "test1234");
            Assert.That(parser.CheckSignature(cert.PublicKey.Key));
        }

        /// <summary>
        /// Ensure that it is not possible to add a response, when a request has already been added.
        /// </summary>
        [Test]
        public void TestIntegrity_01()
        {
            HttpRedirectBindingBuilder binding = new HttpRedirectBindingBuilder();
            binding.Request = "Request";
            try
            {
                binding.Response = "Response";
                Assert.Fail("HttpRedirectBinding did not throw an exception when both Request and Response were set.");
            } catch(ArgumentException) { }
        }
        
        /// <summary>
        /// Ensure that it is not possible to add a request, when a response has already been added.
        /// </summary>
        [Test]
        public void TestIntegrity_02()
        {
            HttpRedirectBindingBuilder binding = new HttpRedirectBindingBuilder();
            binding.Response = "Response";
            try
            {
                binding.Request = "Request";
                Assert.Fail("HttpRedirectBinding did not throw an exception when both Request and Response were set.");
            } catch(ArgumentException) { }
        }

        /// <summary>
        /// Uses a RSA key to sign and verify the Authentication request.
        /// </summary>
        [Test]
        public void TestRSASigning()
        {
            HttpRedirectBindingBuilder binding = new HttpRedirectBindingBuilder();
                        
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();           
            binding.signingKey = key;
            binding.Request = string.Empty.PadLeft(500, 'a');

            // Parse the result
            Uri url = new Uri("http://localhost/?" + binding.ToQuery());
            HttpRedirectBindingParser parser = new HttpRedirectBindingParser(url);
            Assert.That(parser.IsSigned);
            Assert.That(parser.IsRequest);
            Assert.That(!parser.IsResponse);

            Assert.That(parser.CheckSignature(key));

            // Create a new key set, and check that it can not verify the signature.
            RSACryptoServiceProvider evilKey = new RSACryptoServiceProvider();
            Assert.IsFalse(parser.CheckSignature(evilKey));
        }

        /// <summary>
        /// Uses a DSA key to sign and verify the Authentication request.
        /// </summary>
        [Test]
        public void TestDSASigning()
        {
            HttpRedirectBindingBuilder binding = new HttpRedirectBindingBuilder();            
            
            DSACryptoServiceProvider key = new DSACryptoServiceProvider();
            binding.signingKey = key;
            binding.Request = string.Empty.PadLeft(500, 'a');

            // Now, parse the query.
            Uri url = new Uri("http://localhost/?" + binding.ToQuery());
            HttpRedirectBindingParser parser = new HttpRedirectBindingParser(url);
            Assert.That(parser.IsSigned);
            Assert.That(parser.IsRequest);
            Assert.That(parser.CheckSignature(key));

            // Create a new key set, and check that it can not verify the signature.
            DSACryptoServiceProvider evilKey = new DSACryptoServiceProvider();
            Assert.IsFalse(parser.CheckSignature(evilKey));
        }

        /// <summary>
        /// Verify that basic encoding and decoding of a Request works.
        /// Verify that the parser correctly detects a Request parameter.
        /// </summary>
        [Test]
        public void TestParsing_01()
        {
            HttpRedirectBindingBuilder bindingBuilder = new HttpRedirectBindingBuilder();
            string request = string.Empty.PadLeft(350, 'A')+"ÆØÅæøå";
            bindingBuilder.Request = request;

            string query = bindingBuilder.ToQuery();
            NameValueCollection coll = QueryToNameValueCollection(query);
            Assert.That(coll.Count == 1);            

            Uri url = new Uri("http://localhost/?" + query);
            HttpRedirectBindingParser bindingParser = new HttpRedirectBindingParser(url);
            Assert.That(bindingParser.IsRequest);
            Assert.That(!bindingParser.IsResponse);
            Assert.That(!bindingParser.IsSigned);
            Assert.AreEqual(request, bindingParser.Message);

            try
            {
                bindingParser.CheckSignature(new RSACryptoServiceProvider());
                Assert.Fail("Trying to verify signature of an unsigned request should have thrown an exception.");
            } catch(InvalidOperationException) {}
        }

        /// <summary>
        /// Verify that basic encoding and decoding of a Request works.
        /// Verify that basic encoding and decoding of a RelayState works.
        /// </summary>
        [Test]
        public void TestParsing_02()
        {
            HttpRedirectBindingBuilder bindingBuilder = new HttpRedirectBindingBuilder();
            string request = string.Empty.PadRight(140, 'l');
            string relaystate = "A relaystate test. @@@!!!&&&///";

            bindingBuilder.Request = request;
            bindingBuilder.RelayState = relaystate;

            string query = bindingBuilder.ToQuery();
            NameValueCollection coll = QueryToNameValueCollection(query);
            Assert.AreEqual(2, coll.Count);

            Uri url = new Uri("http://localhost/?" + query);
            HttpRedirectBindingParser bindingParser = new HttpRedirectBindingParser(url);
            Assert.IsTrue(bindingParser.IsRequest);
            Assert.IsFalse(bindingParser.IsResponse);
            Assert.IsFalse(bindingParser.IsSigned);
            Assert.IsNotNull(bindingParser.RelayState );
            Assert.AreEqual(relaystate, bindingParser.RelayStateDecoded);
            Assert.AreEqual(request, bindingParser.Message);
        }

        /// <summary>
        /// Tests that Relaystate is encoded at the correct times.
        /// </summary>
        [Test]
        public void TestRelaystate_01()
        {
            HttpRedirectBindingBuilder bindingBuilder = new HttpRedirectBindingBuilder();
            bindingBuilder.Request = "A random request... !!!! .... ";
            string relaystate = string.Empty.PadRight(10, 'A');
            bindingBuilder.RelayState = relaystate;

            // When using the builder to create a request, the relaystate should be encoded.
            string query = bindingBuilder.ToQuery();
            Assert.That(!query.Contains(relaystate));            
        }
        
        /// <summary>
        /// Tests that Relaystate is encoded at the correct times.
        /// </summary>
        [Test]
        public void TestRelaystate_02()
        {
            HttpRedirectBindingBuilder bindingBuilder = new HttpRedirectBindingBuilder();
            bindingBuilder.Response = "A random response... !!!! .... ";
            string relaystate = string.Empty.PadRight(10, 'A');
            bindingBuilder.RelayState = relaystate;

            // When using the builder to create a response, the relaystate 
            // should not be encoded, and can thus be located in the query-string
            string query = bindingBuilder.ToQuery();
            Assert.That(query.Contains(relaystate));
        }

        /// <summary>
        /// Performs a simple split of an Url query, and stores the result in a NameValueCollection.
        /// This method may fail horribly if the query string is not correctly URL-encoded.
        /// </summary>
        public static NameValueCollection QueryToNameValueCollection(string request)
        {
            if (request[0] == '?')
                request = request.Substring(1);

            NameValueCollection result = new NameValueCollection();
            foreach (string s in request.Split('&'))
            {
                string[] keyvalue = s.Split('=');
                result.Add(keyvalue[0], keyvalue[1]);
            }

            return result;
        }

    }
}