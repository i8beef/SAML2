using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Web;
using System.Xml;
using SAML2.Logging;
using SAML2.Config;

namespace SAML2.Bindings
{
    /// <summary>
    /// Implements the HTTP SOAP binding
    /// </summary>
    public class HttpSoapBindingBuilder
    {
        /// <summary>
        /// The current http context
        /// </summary>
        protected HttpContext Context;

        /// <summary>
        /// Logger instance.
        /// </summary>
        protected static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSoapBindingBuilder"/> class.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        public HttpSoapBindingBuilder(HttpContext context)
        {
            Context = context;
        }

        /// <summary>
        /// Sends a response message.
        /// </summary>
        /// <param name="samlMessage">The saml message.</param>
        public void SendResponseMessage(string samlMessage)
        {
            Context.Response.ContentType = "text/xml";
            var writer = new StreamWriter(Context.Response.OutputStream);
            writer.Write(WrapInSoapEnvelope(samlMessage));
            writer.Flush();
            writer.Close();
            Context.Response.End();
        }

        /// <summary>
        /// Wraps a message in a SOAP envelope.
        /// </summary>
        /// <param name="s">The s.</param>
        /// <returns></returns>
        public string WrapInSoapEnvelope(string s)
        {
            var builder = new StringBuilder();

            builder.AppendLine(SoapConstants.EnvelopeBegin);
            builder.AppendLine(SoapConstants.BodyBegin);
            builder.AppendLine(s);
            builder.AppendLine(SoapConstants.BodyEnd);
            builder.AppendLine(SoapConstants.EnvelopeEnd);

            return builder.ToString();
        }

        /// <summary>
        /// Validates the server certificate.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="chain">The chain.</param>
        /// <param name="sslPolicyErrors">The SSL policy errors.</param>
        /// <returns>True if validation of the server certificate generates no policy errors</returns>
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return sslPolicyErrors == SslPolicyErrors.None;
        }

        /// <summary>
        /// Creates a WCF SSL binding.
        /// </summary>
        /// <returns>The WCF SSL binding.</returns>
        private static Binding CreateSslBinding()
        {
            return new BasicHttpBinding(BasicHttpSecurityMode.Transport) { TextEncoding = Encoding.UTF8 };
        }

        /// <summary>
        /// Gets a response from the IdP based on a message.
        /// </summary>
        /// <param name="endpoint">The IdP endpoint.</param>
        /// <param name="message">The message.</param>
        /// <param name="basicAuth">Basic auth settings.</param>
        /// <returns>The Stream.</returns>
        public Stream GetResponse(string endpoint, string message, HttpBasicAuthElement basicAuth)
        {
            var binding = CreateSslBinding();
            var request = Message.CreateMessage(binding.MessageVersion, HttpArtifactBindingConstants.SoapAction, new SimpleBodyWriter(message));
            request.Headers.To = new Uri(endpoint);

            var property = new HttpRequestMessageProperty { Method = "POST" };
            property.Headers.Add(HttpRequestHeader.ContentType, "text/xml; charset=utf-8");
            
            // We are using Basic http auth over ssl
            if (basicAuth != null && basicAuth.Enabled)
            {
                var basicAuthzHeader = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(basicAuth.Username + ":" + basicAuth.Password));
                property.Headers.Add(HttpRequestHeader.Authorization, basicAuthzHeader);
            }
            
            request.Properties.Add( HttpRequestMessageProperty.Name, property );
            if (Context.Request.Params["relayState"] != null)
            {
                request.Properties.Add("relayState", Context.Request.Params["relayState"]);
            }          
  
            var epa = new EndpointAddress(endpoint);

            var factory = new ChannelFactory<IRequestChannel>(binding, epa);
            var reqChannel = factory.CreateChannel();
            
            reqChannel.Open();
            var response = reqChannel.Request(request);
            Console.WriteLine(response);
            reqChannel.Close();

            var xDoc = new XmlDocument();
            xDoc.Load(response.GetReaderAtBodyContents());
            var outerXml = xDoc.DocumentElement.OuterXml;
            var memStream = new MemoryStream(Encoding.UTF8.GetBytes(outerXml));

            return memStream;
        }

        /// <summary>
        /// A simple body writer
        /// </summary>
        internal class SimpleBodyWriter : BodyWriter
        {
            /// <summary>
            /// The message.
            /// </summary>
            private readonly string _message;

            /// <summary>
            /// Initializes a new instance of the <see cref="SimpleBodyWriter"/> class.
            /// </summary>
            /// <param name="message">The message.</param>
            public SimpleBodyWriter(string message)
                : base(false)
            {
                _message = message;
            }

            /// <summary>
            /// When implemented, provides an extensibility point when the body contents are written.
            /// </summary>
            /// <param name="writer">The <see cref="T:System.Xml.XmlDictionaryWriter"/> used to write out the message body.</param>
            protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
            {
                writer.WriteRaw(_message);
            }
        }
    }
}