using System;
using System.IO;
using System.Net;
using System.Net.Mime;
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
    public class HttpSOAPBindingBuilder
    {
        /// <summary>
        /// The current http context
        /// </summary>
        protected HttpContext _context;

        /// <summary>
        /// Logger instance.
        /// </summary>
        protected static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSOAPBindingBuilder"/> class.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        public HttpSOAPBindingBuilder(HttpContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Sends a response message.
        /// </summary>
        /// <param name="samlMessage">The saml message.</param>
        public void SendResponseMessage(string samlMessage)
        {
            _context.Response.ContentType = "text/xml";
            StreamWriter writer = new StreamWriter(_context.Response.OutputStream);
            writer.Write(WrapInSoapEnvelope(samlMessage));
            writer.Flush();
            writer.Close();
            _context.Response.End();
        }

        /// <summary>
        /// Wraps a message in a SOAP envelope.
        /// </summary>
        /// <param name="s">The s.</param>
        /// <returns></returns>
        public string WrapInSoapEnvelope(string s)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(SOAPConstants.EnvelopeBegin);
            builder.AppendLine(SOAPConstants.BodyBegin);
            builder.AppendLine(s);
            builder.AppendLine(SOAPConstants.BodyEnd);
            builder.AppendLine(SOAPConstants.EnvelopeEnd);

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
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;
            return false;
        }

        /// <summary>
        /// Creates a WCF SSL binding.
        /// </summary>
        /// <returns></returns>
        private static Binding CreateSslBinding()
        {
            BasicHttpBinding binding = new BasicHttpBinding(BasicHttpSecurityMode.Transport);
            binding.TextEncoding = Encoding.UTF8;
            return binding;
        }

        /// <summary>
        /// Gets a response from the IdP based on a message.
        /// </summary>
        /// <param name="endpoint">The IdP endpoint.</param>
        /// <param name="message">The message.</param>
        /// <param name="basicAuth">Basic auth settings.</param>
        /// <returns></returns>
        public Stream GetResponse(string endpoint, string message, HttpBasicAuthElement basicAuth)
        {
            Binding binding = CreateSslBinding();
            Message request = Message.CreateMessage(binding.MessageVersion, HttpArtifactBindingConstants.SOAPAction, new SimpleBodyWriter(message));
            
            request.Headers.To = new Uri(endpoint);

            HttpRequestMessageProperty property = new HttpRequestMessageProperty();
            property.Method = "POST";
            property.Headers.Add(HttpRequestHeader.ContentType, "text/xml; charset=utf-8");
            
            //We are using Basic http auth over ssl
            if (basicAuth != null && basicAuth.Enabled)
            {
                string basicAuthzHeader = "Basic " +
                                          Convert.ToBase64String(Encoding.UTF8.GetBytes(basicAuth.Username + ":" + basicAuth.Password));
                property.Headers.Add(HttpRequestHeader.Authorization, basicAuthzHeader);
            }
            
            request.Properties.Add( HttpRequestMessageProperty.Name, property );
            if (_context.Request.Params["relayState"] != null)
                request.Properties.Add("relayState", _context.Request.Params["relayState"]);          
  
            EndpointAddress epa = new EndpointAddress(endpoint);

            ChannelFactory<IRequestChannel> factory = new ChannelFactory<IRequestChannel>(binding, epa);
            IRequestChannel reqChannel = factory.CreateChannel();
            
            reqChannel.Open();
            Message response = reqChannel.Request(request);
            Console.WriteLine(response);
            reqChannel.Close();
            XmlDocument xDoc = new XmlDocument();
            xDoc.Load(response.GetReaderAtBodyContents());
            string outerXml = xDoc.DocumentElement.OuterXml;
            MemoryStream memStream = new MemoryStream(Encoding.UTF8.GetBytes(outerXml));
            return memStream;
        
        }
    }

    /// <summary>
    /// A simple body writer
    /// </summary>
    internal class SimpleBodyWriter : BodyWriter
    {
        private string _message;
        
        public SimpleBodyWriter(string message) : base(false)
        {
            _message = message;
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteRaw(_message);
        }
    }
}