using System;
using System.Xml;
using SAML2.config;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using Saml2.Properties;

namespace SAML2
{
    /// <summary>
    /// Encapsulates the LogoutRequest schema class
    /// </summary>
    public class Saml20LogoutRequest
    {
        #region Private variables

        private LogoutRequest _request;

        #endregion

        #region Constructor functions

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20LogoutRequest"/> class.
        /// </summary>
        public Saml20LogoutRequest()
        {
            _request = new LogoutRequest();
            _request.Version = Saml20Constants.Version;
            _request.ID = "id" + Guid.NewGuid().ToString("N");
            _request.Issuer = new NameID();
            _request.IssueInstant = DateTime.Now;
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the reason for this logout request.
        /// Defined values should be on uri form.
        /// </summary>
        /// <value>The reason.</value>
        public string Reason
        {
            get { return _request.Reason; }
            set { _request.Reason = value; }
        }

        /// <summary>
        /// Gets or sets NotOnOrAfter.
        /// </summary>
        /// <value>NotOnOrAfter.</value>
        public DateTime? NotOnOrAfter
        {
            get { return _request.NotOnOrAfter; }
            set { _request.NotOnOrAfter = value; }
        }

        /// <summary>
        /// Gets or sets SubjectToLogOut.
        /// </summary>
        /// <value>SubjectToLogOut.</value>
        public NameID SubjectToLogOut
        {
            get { return _request.Item as NameID; }
            set { _request.Item = value; }
        }

        /// <summary>
        /// Gets or sets the destination.
        /// </summary>
        /// <value>The destination.</value>
        public string Destination
        {
            get { return _request.Destination; }
            set { _request.Destination = value; }
        }

        /// <summary>
        /// Gets or sets the SessionIndex.
        /// </summary>
        /// <value>The SessionIndex.</value>
        public string SessionIndex
        {
            get { return _request.SessionIndex[0]; }
            set { _request.SessionIndex = new string[]{value};}
        }

        /// <summary>
        /// Gets or sets the issuer value.
        /// </summary>
        /// <value>The issuer value.</value>
        public string Issuer
        {
            get { return _request.Issuer.Value; }
            set { _request.Issuer.Value = value; }
        }

        /// <summary>
        /// Gets the underlying LogoutRequest schema class instance.
        /// </summary>
        /// <value>The request.</value>
        public LogoutRequest Request
        {
            get { return _request; }
        }

        #endregion

        /// <summary>
        /// Returns the AuthnRequest as an XML document.
        /// </summary>
        public XmlDocument GetXml()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(Serialization.SerializeToXmlString(_request));
            return doc;
        }

        /// <summary>
        /// Returns the id of the logout request.
        /// </summary>
        public string ID
        {
            get { return _request.ID; }
        }
        
        /// <summary>
        /// Returns an instance of the class with meaningful default values set.
        /// </summary>
        /// <returns></returns>
        public static Saml20LogoutRequest GetDefault()
        {
            Saml20LogoutRequest result = new Saml20LogoutRequest();
            result.SubjectToLogOut = new NameID();
            //format
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            if (config.ServiceProvider == null || string.IsNullOrEmpty(config.ServiceProvider.ID))
                throw new Saml20FormatException(Resources.ServiceProviderNotSet);

            result.Issuer = config.ServiceProvider.ID;

            return result;

        }
    }
}
