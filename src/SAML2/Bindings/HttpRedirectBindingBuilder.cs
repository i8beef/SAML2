using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using CONSTS = SAML2.Bindings.HttpRedirectBindingConstants;

namespace SAML2.Bindings
{
    /// <summary>
    /// Handles the creation of redirect locations when using the HTTP redirect binding, which is outlined in [SAMLBind] 
    /// section 3.4. 
    /// </summary>
    public class HttpRedirectBindingBuilder
    {
        #region Properties

        private string _request;

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        /// <value>The request.</value>
        public string Request
        {
            get { return _request; }
            set
            {
                if (!string.IsNullOrEmpty(_response))
                    throw new ArgumentException("Response property is already specified. Unable to set Request property.");

                _request = value;
            }
        }

        private string _response;
        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        /// <value>The response.</value>
        public string Response
        {
            get { return _response; }
            set
            {
                if (!string.IsNullOrEmpty(_request))
                    throw new ArgumentException("Request property is already specified. Unable to set Response property.");

                _response = value;
            }
        }

        private string _relayState;

        /// <summary>
        /// <para>Sets the relaystate of the message.</para>
        /// <para>If the message being built is a response message, the relaystate will be included unmodified.</para>
        /// <para>If the message being built is a request message, the relaystate will be encoded and compressed before being included.</para>
        /// </summary>
        public string RelayState
        {
            get { return _relayState; }
            set { _relayState = value; }
        }

        private AsymmetricAlgorithm _signingKey;

        /// <summary>
        /// Gets or sets the signing key.
        /// </summary>
        /// <value>The signing key.</value>
        public AsymmetricAlgorithm signingKey
        {
            set
            {
                // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
                if (!(value is RSACryptoServiceProvider || value is DSA || value == null))
                    throw new ArgumentException("Signing key must be an instance of either RSACryptoServiceProvider or DSA.");
                _signingKey = value;
            }

            get { return _signingKey; }
        }

        #endregion

        /// <summary>
        /// Returns the query part of the url that should be redirected to.
        /// The resulting string should be pre-pended with either ? or &amp; before use.
        /// </summary>
        public string ToQuery()
        {
            StringBuilder result = new StringBuilder();

            AddMessageParameter(result);
            AddRelayState(result);
            AddSignature(result);

            return result.ToString();
        }

        /// <summary>
        /// If an asymmetric key has been specified, sign the request.
        /// </summary>        
        private void AddSignature(StringBuilder result)
        {
            if (_signingKey == null)
                return;

            result.Append(string.Format("&{0}=", HttpRedirectBindingConstants.SigAlg));

            if (_signingKey is RSA)
                result.Append(UpperCaseUrlEncode(HttpUtility.UrlEncode(SignedXml.XmlDsigRSASHA1Url)));
            else
                result.Append(UpperCaseUrlEncode(HttpUtility.UrlEncode(SignedXml.XmlDsigDSAUrl)));

            // Calculate the signature of the URL as described in [SAMLBind] section 3.4.4.1.            
            byte[] signature = SignData(Encoding.UTF8.GetBytes(result.ToString()));            
            
            result.AppendFormat("&{0}=", HttpRedirectBindingConstants.Signature);
            result.Append(HttpUtility.UrlEncode(Convert.ToBase64String(signature)));
        }

        /// <summary>
        /// Uppercase the URL-encoded parts of the string. Needed because Ping does not seem to be able to handle lower-cased URL-encodings.
        /// </summary>
        private static string UpperCaseUrlEncode(string s)
        {
            StringBuilder result = new StringBuilder(s);
            for (int i = 0 ; i < result.Length ; i++)
            {
                if (result[i] == '%')
                {
                    result[++i] = Char.ToUpper(result[i]);
                    result[++i] = Char.ToUpper(result[i]);
                }
            }                        
            return result.ToString();
        }

        /// <summary>
        /// Create the signature for the data.
        /// </summary>
        private byte[] SignData(byte[] data)
        {
            if (_signingKey is RSACryptoServiceProvider)
            {
                RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)_signingKey;
                return rsa.SignData(data, new SHA1CryptoServiceProvider());
            } 
            else
            {
                DSACryptoServiceProvider dsa = (DSACryptoServiceProvider)_signingKey;
                return dsa.SignData(data);
            }
        }

        /// <summary>
        /// If the RelayState property has been set, this method adds it to the query string.
        /// </summary>
        /// <param name="result"></param>
        private void AddRelayState(StringBuilder result)
        {
            if (_relayState == null)
                return;

            result.Append("&RelayState=");
            // Encode the relay state if we're building a request. Otherwise, append unmodified.
            if (_request != null)
                result.Append(HttpUtility.UrlEncode(DEFLATEEncode(_relayState)));
            else
                result.Append(_relayState);
        }

        /// <summary>
        /// Depending on which one is specified, this method adds the SAMLRequest or SAMLResponse parameter to the URL query.
        /// </summary>
        private void AddMessageParameter(StringBuilder result)
        {
            if (!(_response == null || _request == null))
                throw new Exception("Request or Response property MUST be set.");

            string value; 
            if (_request != null)
            {
                result.AppendFormat("{0}=", CONSTS.SAMLRequest);
                value = _request;
            }
            else
            {
                result.AppendFormat("{0}=", HttpRedirectBindingConstants.SAMLResponse);
                value = _response;
            }
            string encoded = DEFLATEEncode(value);
            result.Append(UpperCaseUrlEncode(HttpUtility.UrlEncode(encoded)));
        }

        /// <summary>
        /// Uses DEFLATE compression to compress the input value. Returns the result as a Base64 encoded string.
        /// </summary>
        private static string DEFLATEEncode(string val)
        {
            MemoryStream memoryStream = new MemoryStream();
            using (StreamWriter writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false)))
            {
                writer.Write(val);                
                writer.Close();
                return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int) memoryStream.Length, Base64FormattingOptions.None);
            }
        }
    }
}