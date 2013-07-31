using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using SAML2;
using SAML2.Bindings;
using SAML2.config;
using SAML2.identity;
using SAML2.Properties;
using SAML2.protocol;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using Saml2.Properties;
using Trace=SAML2.Utils.Trace;

namespace SAML2
{
    /// <summary>
    /// Performs SAML2.0 attribute queries
    /// </summary>
    public class Saml20AttributeQuery
    {
        private readonly AttributeQuery _attrQuery;

        private readonly List<SamlAttribute> _attributes;

        private Saml20AttributeQuery()
        {
            _attrQuery = new AttributeQuery();
            _attrQuery.Version = Saml20Constants.Version;
            _attrQuery.ID = "id" + Guid.NewGuid().ToString("N");
            _attrQuery.Issuer = new NameID();
            _attrQuery.IssueInstant = DateTime.Now;
            _attrQuery.Subject = new Subject();
            _attributes = new List<SamlAttribute>();

        }

        /// <summary>
        /// Gets or sets the issuer of the attribute query.
        /// </summary>
        /// <value>The issuer.</value>
        public string Issuer
        {
            get { return _attrQuery.Issuer.Value; }
            set { _attrQuery.Issuer.Value = value; }
        }

        /// <summary>
        /// Gets the ID of the attribute query.
        /// </summary>
        /// <value>The ID.</value>
        public string ID
        {
            get { return _attrQuery.ID; }
        }

        /// <summary>
        /// Adds an attribute to be queried using basic name format.
        /// </summary>
        /// <param name="attrName">Name of the attribute.</param>
        public void AddAttribute(string attrName)
        {
            AddAttribute(attrName, Saml20NameFormat.BASIC);
        }

        /// <summary>
        /// Adds an attribute by name using the specified name format.
        /// </summary>
        /// <param name="attrName">Name of the attribute.</param>
        /// <param name="nameFormat">The name format of the attribute.</param>
        public void AddAttribute(string attrName, Saml20NameFormat nameFormat)
        {
            List<SamlAttribute> found = _attributes.FindAll(delegate(SamlAttribute at) { return at.Name == attrName && at.NameFormat == GetNameFormat(nameFormat); });
            if (found.Count > 0)
                throw new InvalidOperationException(
                    string.Format("An attribute with name \"{0}\" and name format \"{1}\" has already been added", attrName, Enum.GetName(typeof(Saml20NameFormat), nameFormat)));
            
            SamlAttribute attr = new SamlAttribute();
            attr.Name = attrName;
            attr.NameFormat = GetNameFormat(nameFormat);

            _attributes.Add(attr);
        }

        private static string GetNameFormat(Saml20NameFormat nameFormat)
        {
            string result;

            switch (nameFormat)
            {
                case Saml20NameFormat.BASIC:
                    result = SamlAttribute.NAMEFORMAT_BASIC;
                    break;
                case Saml20NameFormat.URI:
                    result = SamlAttribute.NAMEFORMAT_URI;
                    break;
                default:
                    throw new ArgumentException(
                        string.Format("Unsupported nameFormat: {0}", Enum.GetName(typeof(Saml20NameFormat), nameFormat)),
                        "nameFormat");
            }

            return result;
        }

        /// <summary>
        /// Performs the attribute query and adds the resulting attributes to Saml20Identity.Current.
        /// </summary>
        /// <param name="context">The http context.</param>
        public void PerformQuery(HttpContext context)
        {
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            string endpointId = context.Session[Saml20AbstractEndpointHandler.IDPLoginSessionKey].ToString();

            if (string.IsNullOrEmpty(endpointId))
            {
                Trace.TraceData(TraceEventType.Information, Tracing.AttrQueryNoLogin);
                throw new InvalidOperationException(Tracing.AttrQueryNoLogin);
            }

            IDPEndPoint ep = config.FindEndPoint(endpointId);

            if (ep == null)
                throw new Saml20Exception(string.Format("Unable to find information about the IdP with id \"{0}\"", endpointId));

            PerformQuery(context, ep);
        }

        /// <summary>
        /// Performs the attribute query against the specified IdP endpoint and adds the resulting attributes to Saml20Identity.Current.
        /// </summary>
        /// <param name="context">The http context.</param>
        /// <param name="endPoint">The IdP to perform the query against.</param>
        public void PerformQuery(HttpContext context, IDPEndPoint endPoint)
        {
            string nameIdFormat = context.Session[Saml20AbstractEndpointHandler.IDPNameIdFormat].ToString();
            if(string.IsNullOrEmpty(nameIdFormat))
                nameIdFormat = Saml20Constants.NameIdentifierFormats.Persistent;
            PerformQuery(context, endPoint, nameIdFormat);
        }

        /// <summary>
        /// Performs the attribute query against the specified IdP endpoint and adds the resulting attributes to Saml20Identity.Current.
        /// </summary>
        /// <param name="context">The http context.</param>
        /// <param name="endPoint">The IdP to perform the query against.</param>
        /// <param name="nameIdFormat">The nameid format.</param>
        public void PerformQuery(HttpContext context, IDPEndPoint endPoint, string nameIdFormat)
        {
            Trace.TraceMethodCalled(GetType(), "PerformQuery()");

            HttpSOAPBindingBuilder builder = new HttpSOAPBindingBuilder(context);
            
            NameID name = new NameID();
            name.Value = Saml20Identity.Current.Name;
            name.Format = nameIdFormat;
            _attrQuery.Subject.Items = new object[] { name };

            _attrQuery.SamlAttribute = _attributes.ToArray();
            XmlDocument query = new XmlDocument();
            query.LoadXml(Serialization.SerializeToXmlString(_attrQuery));

            XmlSignatureUtils.SignDocument(query, ID);
            if(query.FirstChild is XmlDeclaration)
                query.RemoveChild(query.FirstChild);

            Stream s;

            if (Trace.ShouldTrace(TraceEventType.Information))
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendAttrQuery, endPoint.metadata.GetAttributeQueryEndpointLocation(), query.OuterXml));

            try
            {
                 s = builder.GetResponse(endPoint.metadata.GetAttributeQueryEndpointLocation(), query.OuterXml,
                                               endPoint.AttributeQuery);

            }catch(Exception e)
            {
                Trace.TraceData(TraceEventType.Error, e.ToString());
                throw;
            }

            HttpSOAPBindingParser parser = new HttpSOAPBindingParser(s);

            Status status = parser.GetStatus();

            if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
            {
                Trace.TraceData(TraceEventType.Error,
                                string.Format(Tracing.AttrQueryStatusError, Serialization.SerializeToXmlString(status)));
                throw new Saml20Exception(status.StatusMessage);
            }

            bool isEncrypted;

            XmlElement xmlAssertion = Saml20SignonHandler.GetAssertion(parser.SamlMessage, out isEncrypted);

            if (isEncrypted)
            {
                Saml20EncryptedAssertion ass =
                    new Saml20EncryptedAssertion(
                        (RSA) FederationConfig.GetConfig().SigningCertificate.GetCertificate().PrivateKey);
                ass.LoadXml(xmlAssertion);
                ass.Decrypt();
                xmlAssertion = ass.Assertion.DocumentElement;
            }

            Saml20Assertion assertion =
                    new Saml20Assertion(xmlAssertion, null, SAML20FederationConfig.GetConfig().Profile, endPoint.QuirksMode);

            if(Trace.ShouldTrace(TraceEventType.Information))
            {
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.AttrQueryAssertion, xmlAssertion == null ? string.Empty : xmlAssertion.OuterXml));
            }

            if(!assertion.CheckSignature(Saml20SignonHandler.GetTrustedSigners(endPoint.metadata.Keys, endPoint))){
                Trace.TraceData(TraceEventType.Error, Resources.SignatureInvalid);
                throw new Saml20Exception(Resources.SignatureInvalid);
            }
            
            foreach (SamlAttribute attr in assertion.Attributes)
            {
                Saml20Identity.Current.AddAttributeFromQuery(attr.Name, attr);
            }
           
        }

        /// <summary>
        /// Gets a default instance of this class with meaningful default values set.
        /// </summary>
        /// <returns></returns>
        public static Saml20AttributeQuery GetDefault()
        {
            Saml20AttributeQuery result = new Saml20AttributeQuery();

            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            if (config.ServiceProvider == null || string.IsNullOrEmpty(config.ServiceProvider.ID))
                throw new Saml20FormatException(Resources.ServiceProviderNotSet);

            result.Issuer = config.ServiceProvider.ID;
            
            return result;
        }

    }

    /// <summary>
    /// Name formats for queried attributes
    /// </summary>
    public enum Saml20NameFormat
    {
        /// <summary>
        /// Basic name format
        /// </summary>
        BASIC,
        /// <summary>
        /// Uri name format
        /// </summary>
        URI,
    }
}