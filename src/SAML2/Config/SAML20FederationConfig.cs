using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using SAML2.identity;
using SAML2.protocol;
using SAML2.Schema.Metadata;
using SAML2.Utils;
using Saml2.Properties;
using Trace=SAML2.Utils.Trace;
using System.Security.Cryptography;

namespace SAML2.config
{
    /// <summary>
    /// Configuration elements for SAML20 Federation
    /// To create a new XSD Run this command:
    /// xsd -t:SAML2.config.SAML20Federation SAML2.dll
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    [XmlRoot(ConfigurationConstants.SectionNames.SAML20Federation, Namespace = ConfigurationConstants.NamespaceUri, IsNullable = false)]    
    public class SAML20FederationConfig : ConfigurationInstance<SAML20FederationConfig>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SAML20FederationConfig"/> class.
        /// </summary>
        public SAML20FederationConfig()
        {
            ServiceProvider = new ServiceProviderElement();
            _idpEndpoints = new IDPEndpoints();                        
        }

        /// <summary>
        /// Requested attributes
        /// </summary>
        [XmlElement]
        public RequestedAttributes RequestedAttributes;

        /// <summary>
        /// Service provider
        /// </summary>
        [XmlElement]
        public ServiceProviderElement ServiceProvider;

        private CommonDomainConfig _commonDomain;

        /// <summary>
        /// Gets or sets the common domain configuration section.
        /// </summary>
        [XmlElement(ElementName = "CommonDomain")]
        public CommonDomainConfig CommonDomain
        {
            get
            {
                if (_commonDomain == null)
                    _commonDomain = new CommonDomainConfig();
                return _commonDomain;
            }
            set
            {
                _commonDomain = value;
            }
        }

        private string _nameIdFormat;

        /// <summary>
        /// Gets or sets the NameIdFormat configuration
        /// </summary>
        [XmlElement(ElementName = "NameIdFormat")]
        public string NameIdFormat
        {
            get { return _nameIdFormat; }
            set { _nameIdFormat = value; }
        }

        // default to false
        private Boolean _showError = false;

        /// <summary>
        /// Gets or sets the ShowError configuration
        /// NOTE: This setting should be FALSE for production, due to XML Encryption being vulnerable to attack
        ///       if information is leaked through error messages
        /// </summary>
        [XmlElement(ElementName = "ShowError")]
        public Boolean ShowError
        {
            get { return _showError; }
            set { _showError = value; }
        }

        /// <summary>
        /// The logger to use, defaults to NoLogging.
        /// </summary>
        private string _logger;

        /// <summary>
        /// Gets or sets the Logger configuration
        /// </summary>
        [XmlElement(ElementName = "Logger")]
        public string Logger
        {
            get { return _logger; }
            set { _logger = value; }
        }

        private IDPEndpoints _idpEndpoints;

        /// <summary>
        /// Gets or sets the IDP endpoints.
        /// </summary>
        /// <value>The IDP endpoints.</value>
        [XmlIgnore]
        public List<IDPEndPoint> IDPEndPoints
        {
            get { return _idpEndpoints.IDPEndPoints; }
            set { _idpEndpoints.IDPEndPoints = value; }
        }

        /// <summary>
        /// Gets or sets the endpoints.
        /// </summary>
        /// <value>The endpoints.</value>
        [XmlElement("IDPEndPoints")]
        public IDPEndpoints Endpoints
        {
            get { return _idpEndpoints; }
            set { _idpEndpoints = value; }
        }

        /// <summary>
        /// Metadata element
        /// </summary>
        [XmlElement("Metadata")] public ConfigMetadata Metadata;

        /// <summary>
        /// Finds an endpoint given its id.
        /// </summary>
        /// <param name="endPointId">The end point id.</param>
        /// <returns></returns>
        public IDPEndPoint FindEndPoint(string endPointId)
        {
            return IDPEndPoints.Find(delegate(IDPEndPoint ep) { return ep.Id == endPointId; });
        }
        
    }

    /// <summary>
    /// Holds common domain configuration for a service provider
    /// </summary>
    public class CommonDomainConfig
    {
        /// <summary>
        /// Is common domain cookie reading enabled
        /// </summary>
        [XmlAttribute(AttributeName = "enabled")]
        public bool Enabled;

        /// <summary>
        /// A full url to the local common domain cookie reader endpoint.
        /// </summary>
        [XmlAttribute(AttributeName = "localReaderEndpoint")]
        public string LocalReaderEndpoint;
    }


    /// <summary>
    /// Configuration element that defines settings for generating metadata.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class ConfigMetadata
    {
        /// <summary>
        /// Artifact protocol binding is not a part of DK-SAML2.0 and should only be included in metadata
        /// when communicating with a non DK-SAML2.0 compliant IdP
        /// </summary>
        [XmlAttribute("IncludeArtifactEndpoints", Namespace = ConfigurationConstants.NamespaceUri)]
        public bool IncludeArtifactEndpoints;
    }

    /// <summary>
    /// Requested attributes configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class RequestedAttributes
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RequestedAttributes"/> class.
        /// </summary>
        public RequestedAttributes()
        {
            Attributes = new List<Attribute>();
        }

        /// <summary>
        /// Attributes
        /// </summary>
        [XmlElement("att")]
        public List<Attribute> Attributes;        


    }

    /// <summary>
    /// Attribute configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]    
    public class Attribute
    {
        /// <summary>
        /// Attribute name, eg. urn:oid:2.5.4.5 or urn:oid:2.5.4.3.
        /// </summary>
        [XmlAttribute("name", Namespace = ConfigurationConstants.NamespaceUri)]
        public string name;

        /// <summary>
        /// Is the attribute required
        /// </summary>
        [XmlAttribute("isRequired", Namespace = ConfigurationConstants.NamespaceUri)]
        public string required;

        /// <summary>
        /// Gets or sets a value indicating whether the attribute is required.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if the attribute is required; otherwise, <c>false</c>.
        /// </value>
        [XmlIgnore]
        public bool IsRequired
        {
            get
            {
                if (string.IsNullOrEmpty(required))
                    return false;

                return Convert.ToBoolean(required);
            }

            set { required = Convert.ToString(value); }
        }
    }


    /// <summary>
    /// Endpoints configuration element.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class IDPEndpoints
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IDPEndpoints"/> class.
        /// </summary>
        public IDPEndpoints()
        {
            IDPEndPoints = new List<IDPEndPoint>();            
            _fileInfo = new Dictionary<string, DateTime>();
            _fileToEntity = new Dictionary<string, string>();
            Refresh();
        }

        /// <summary>
        /// The directory in which the metadata files of trusted identity providers should be found.
        /// </summary>
        [XmlAttribute("metadata")]        
        public string metadataLocation;

        /// <summary>
        /// The encodings that should be attempted when a metadata file does not contain an encoding attribute and 
        /// the signature doesn't validate. Contains a space-delimited list of encoding names to try out.
        /// </summary>
        [XmlAttribute("encodings")]
        public string encodings;

        /// <summary>
        /// URL to a page that is used, in case more than one IDPEndPoint is configured, 
        /// AND no Common Domain Cookie is set AND no default IDP is selected with the default-attribute.
        /// </summary>
        [XmlAttribute("idpSelectionUrl")]
        public string idpSelectionUrl;

        /// <summary>
        /// Contains Encoding instances of the the encodings that should by tried when a metadata file does not have its
        /// encoding specified.
        /// </summary>
        [XmlIgnore]
        private List<Encoding> _encodings;

        /// <summary>
        /// Finds an endpoint given its id.
        /// </summary>
        /// <param name="endPointId">The endpoint's id.</param>
        /// <returns></returns>
        public IDPEndPoint FindEndPoint(string endPointId)
        {
            return IDPEndPoints.Find(delegate(IDPEndPoint ep) { return ep.Id == endPointId; });
        }

        /// <summary>
        /// Returns a list of the encodings that should be tried when a metadata file does not contain a valid signature 
        /// or cannot be loaded by the XmlDocument class. Either returns a list specified by the administrator in the configuration file
        /// or a default list.
        /// </summary>
        private List<Encoding> _getEncodings()
        {
            if (_encodings != null)
                return _encodings;
            
            if (string.IsNullOrEmpty(encodings))
            {
                // If it has not been specified in the config file, use the defaults.
                _encodings = new List<Encoding>();
                _encodings.Add(Encoding.UTF8);
                _encodings.Add(Encoding.GetEncoding("iso-8859-1"));
                return _encodings;
            }
            
            string[] encs = encodings.Split(' ');
            _encodings = new List<Encoding>(encs.Length);
            foreach (string enc in encs)
                _encodings.Add(Encoding.GetEncoding(enc));

            return _encodings;
        }

        /// <summary>
        /// List of IdP endpoints
        /// </summary>
        [XmlElement("add")]        
        public List<IDPEndPoint> IDPEndPoints;

        #region Handling of metadata files 

        /// <summary>
        /// A list of the files that have currently been loaded. The filename is used as key, while last seen modification time is used as value.
        /// </summary>
        [XmlIgnore]
        private Dictionary<string, DateTime> _fileInfo;

        /// <summary>
        /// This dictionary links a file name to the entity id of the metadata document in the file.
        /// </summary>
        [XmlIgnore] 
        private Dictionary<string, string> _fileToEntity;

        /// <summary>
        /// Refreshes the information retrieved from the directory containing metadata files.
        /// </summary>
        public void Refresh()
        {
            if (metadataLocation == null)
                return;

            if (!Directory.Exists(metadataLocation))
                throw new DirectoryNotFoundException(Resources.MetadataLocationNotFoundFormat(metadataLocation));

            // Start by removing information on files that are no long in the directory.
            List<string> keys = new List<string>(_fileInfo.Keys.Count);
            keys.AddRange(_fileInfo.Keys);
            foreach (string file in keys)
                if (!File.Exists(file))
                {
                    _fileInfo.Remove(file);
                    if (_fileToEntity.ContainsKey(file))
                    {
                        IDPEndPoint endp = FindEndPoint(_fileToEntity[file]);
                        if (endp != null)
                            endp.metadata = null;
                        _fileToEntity.Remove(file);
                    }                    
                }

            // Detect added classes
            string[] files = Directory.GetFiles(metadataLocation);
            foreach (string file in files)
            {
                Saml20MetadataDocument metadataDoc;
                if (_fileInfo.ContainsKey(file))
                {
                    if (_fileInfo[file] != File.GetLastWriteTime(file))                    
                        metadataDoc = ParseFile(file);                                            
                    else
                        continue;                    
                } else
                {
                    metadataDoc = ParseFile(file);
                }

                if (metadataDoc != null)
                {
                    IDPEndPoint endp = FindEndPoint(metadataDoc.EntityId);
                    if (endp == null) // If the endpoint does not exist, create it.
                    {                        
                        endp = new IDPEndPoint();                        
                        IDPEndPoints.Add(endp);
                    }

                    endp.Id = endp.Name = metadataDoc.EntityId; // Set some default valuDes.
                    endp.metadata = metadataDoc;                    

                    if (_fileToEntity.ContainsKey(file))
                        _fileToEntity.Remove(file);

                    _fileToEntity.Add(file, metadataDoc.EntityId);
                }
            }
        }

        /// <summary>
        /// Parses the metadata files found in the directory specified in the configuration.
        /// </summary>
        private Saml20MetadataDocument ParseFile(string file)
        {            
            XmlDocument doc = LoadFileAsXmlDocument(file);
            //_fileInfo[file] = File.GetLastWriteTime(file); // Mark that we have seen the file.
            try
            {
                foreach (XmlNode child in doc.ChildNodes)
                {
                    if (child.NamespaceURI == Saml20Constants.METADATA)
                    {
                        if (child.LocalName == EntityDescriptor.ELEMENT_NAME)
                            return new Saml20MetadataDocument(doc);                                                    

                        // TODO Decide how to handle several entities in one metadata file.
                        if (child.LocalName == EntitiesDescriptor.ELEMENT_NAME)
                            throw new NotImplementedException();                                                                            
                    }
                }
                
                // No entity descriptor found. 
                throw new InvalidDataException(); // BAIIIIIIL!!                
            } catch(Exception e)
            {
                // Probably not a metadata file.
                Trace.TraceData(TraceEventType.Error, file, "Probably not a SAML2.0 metadata file.", e.ToString());
                return null;
            }            
        }

        /// <summary>
        /// Loads a file into an XmlDocument. If the loading or the signature check fails, the method will retry using another encoding.
        /// </summary>        
        private XmlDocument LoadFileAsXmlDocument(string filename)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            
            try
            {
                // First attempt a standard load, where the XML document is expected to declare its encoding by itself.
                doc.Load(filename);
                try
                {
                    if (XmlSignatureUtils.IsSigned(doc) && !XmlSignatureUtils.CheckSignature(doc))
                        throw new InvalidOperationException("Invalid file signature");
                            // Throw an exception to get into quirksmode.
                }catch(CryptographicException)
                {
                    //Ignore cryptographic exception caused by Geneva server's inability to generate a
                    //.net compliant xml signature
                    return ParseGenevaServerMetadata(doc);
                }
                return doc;
            }
            catch (XmlException)
            {                
                // Enter quirksmode
                List<Encoding> encs = _getEncodings();
                foreach (Encoding encoding in encs)
                {
                    StreamReader reader = null;
                    try
                    {
                        reader = new StreamReader(filename, encoding);                        
                        doc.Load(reader);
                        if (XmlSignatureUtils.IsSigned(doc) && !XmlSignatureUtils.CheckSignature(doc))
                            continue;                        
                    }
                    catch (XmlException) 
                        { continue; }
                    finally
                    {
                        if (reader != null) 
                            reader.Close();
                    }

                    return doc;
                }
            }
            return null;
        }

        private static XmlDocument ParseGenevaServerMetadata(XmlDocument doc)
        {
            if (doc == null) throw new ArgumentNullException("doc");
            if( doc.DocumentElement == null) throw new ArgumentException("DocumentElement cannot be null", "doc");
            XmlDocument other = new XmlDocument();
            other.PreserveWhitespace = true;
            
            other.LoadXml(doc.OuterXml);

            List<XmlNode> remove = new List<XmlNode>();

            foreach(XmlNode node in other.DocumentElement.ChildNodes)
            {
                if(node.Name != IDPSSODescriptor.ELEMENT_NAME)
                {
                    remove.Add(node);
                }
            }

            foreach (XmlNode node in remove)
            {
                other.DocumentElement.RemoveChild(node);
            }

            return other;
        }

        #endregion
    }

    /// <summary>
    /// Service provider configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class ServiceProviderElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ServiceProviderElement"/> class.
        /// </summary>
        public ServiceProviderElement()
        {
            ContactPerson = new List<Contact>();
            NameIdFormats = new NameIdFormatsElement();
        }

        private string _id;

        /// <summary>
        /// Gets or sets the ID.
        /// </summary>
        /// <value>The ID.</value>
        [XmlAttribute(AttributeName = "id")]
        public string ID
        {
            get
            {
                #if DEBUG
                if (_id == "urn:")
                {
                    string machineName = Environment.MachineName.ToLower();
                    return "urn:" + machineName.Substring(0, 1).ToUpper() + machineName.Remove(0, 1);
                }
                #endif

                return _id;
            }
            set
            {
                if (!Uri.IsWellFormedUriString(value, UriKind.RelativeOrAbsolute))
                    throw new ConfigurationErrorsException(Resources.InvalidWellformedAbsoluteUriStringFormat(value));

                _id = value;
            }
        }

        
        private string _server;

        /// <summary>
        /// Gets or sets the server.
        /// </summary>
        /// <value>The server.</value>
        [XmlAttribute(AttributeName = "server")]
        public string Server
        {
            get
            {
                #if DEBUG
                if (_server == "http://" || _server == "https://")
                    return _server + Environment.MachineName.ToLower() + "." + Environment.GetEnvironmentVariable("USERDNSDOMAIN").ToLower();
                #endif
                return _server;
            }
            set { _server = value; }
        }

        /// <summary>
        /// List of service endpoints
        /// </summary>
        [XmlElement("ServiceEndpoint")] public List<Saml20ServiceEndpoint> serviceEndpoints;

        /// <summary>
        /// Gets the logout endpoint.
        /// </summary>
        /// <value>The logout endpoint.</value>
        public Saml20ServiceEndpoint LogoutEndpoint
        {
            get
            {
                return FindEndpoint(EndpointType.LOGOUT);
            }
        }

        /// <summary>
        /// Gets the sign on endpoint.
        /// </summary>
        /// <value>The sign on endpoint.</value>
        public Saml20ServiceEndpoint SignOnEndpoint
        {
            get
            {
                return FindEndpoint(EndpointType.SIGNON);
            }
        }

        /// <summary>
        /// Gets the metadata endpoint.
        /// </summary>
        /// <value>The metadata endpoint.</value>
        public Saml20ServiceEndpoint MetadataEndpoint
        {
            get
            {
                return FindEndpoint(EndpointType.METADATA);
            }
        }

        /// <summary>
        /// Supported NameIdFormats
        /// </summary>
        public NameIdFormatsElement NameIdFormats;

        private Saml20ServiceEndpoint FindEndpoint(EndpointType type)
        {
            return serviceEndpoints.Find(delegate(Saml20ServiceEndpoint ep) { return ep.endpointType == type; });
        }

        /// <summary>
        /// Organization
        /// </summary>
        [XmlElement(Namespace = Saml20Constants.METADATA)] 
        public Organization Organization;

        /// <summary>
        /// Contact person
        /// </summary>
        [XmlElement(Namespace = Saml20Constants.METADATA)] 
        public List<Contact> ContactPerson;
    }

    /// <summary>
    /// Holds NameIdFormats supported by the service provider
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class NameIdFormatsElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NameIdFormatsElement"/> class.
        /// </summary>
        public NameIdFormatsElement()
        {
            NameIdFormats = new List<NameIdFormatElement>();
        }

        /// <summary>
        /// Shorthand for supporting all NameIdFormats
        /// </summary>
        [XmlAttribute(AttributeName="all")]
        public bool All;

        /// <summary>
        /// List of supported NameFormatIds
        /// </summary>
        [XmlElement(ElementName = "add")]
        public List<NameIdFormatElement> NameIdFormats;
    }

    /// <summary>
    /// An element that holds a single supported NameIdFormat
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class NameIdFormatElement
    {
        /// <summary>
        /// The NameIdFormat
        /// </summary>
        [XmlAttribute(AttributeName="nameIdFormat")]
        public string NameIdFormat;
    }

    /// <summary>
    /// The service provider behaviour configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public enum ServiceProviderBehaviour
    {
        /// <summary>
        /// Keep token
        /// </summary>
        KeepToken,
        /// <summary>
        /// Translate token
        /// </summary>
        TranslateToken
    }

    /// <summary>
    /// The Saml20Service endpoint configuration element
    /// </summary>
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class Saml20ServiceEndpoint
    {
        /// <summary>
        /// The local path to the url on which this endpoint should be placed.
        /// </summary>
        [XmlAttribute("localpath")]
        public string localPath;

        /// <summary>
        /// Type of endpoint
        /// </summary>
        [XmlAttribute("type")]
        public EndpointType endpointType;

        /// <summary>
        /// Numeric index of this endpoint
        /// </summary>
        [XmlAttribute("index")] 
        public ushort endPointIndex;

        /// <summary>
        /// Redirect to this url on succesful request
        /// </summary>
        [XmlAttribute("redirectUrl")] 
        public string RedirectUrl;

        /// <summary>
        /// Saml binding
        /// </summary>
        [XmlAttribute("binding")]
        public SAMLBinding Binding = SAMLBinding.NOT_SET;

        /// <summary>
        /// Error handling behaviour
        /// </summary>
        [XmlAttribute("errorBehaviour")]
        public ErrorBehaviour ErrorBehaviour = ErrorBehaviour.SHOWPAGE;
    }

    /// <summary>
    /// Endpoint types (signon, logout or metadata)
    /// </summary>
    public enum EndpointType
    {
        /// <summary>
        /// Signon endpoint
        /// </summary>
        [XmlEnum("signon")]
        SIGNON,
        /// <summary>
        /// Logout endpoint
        /// </summary>
        [XmlEnum("logout")]
        LOGOUT,
        /// <summary>
        /// Metadata endpoint
        /// </summary>
        [XmlEnum("metadata")]
        METADATA
    }

    /// <summary>
    /// Error handling behaviour (showpage, throwexception)
    /// </summary>
    public enum ErrorBehaviour
    {
        /// <summary>
        /// ShowPage behaviour
        /// </summary>
        [XmlEnum("showpage")]
        SHOWPAGE,
        /// <summary>
        /// ThrowException behaviour
        /// </summary>
        [XmlEnum("throwexception")]
        THROWEXCEPTION
    }

    /// <summary>
    /// the IDPEndpoint configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class IDPEndPoint
    {
        /// <summary>
        /// The metadata associated with the endpoint.
        /// </summary>
        [XmlIgnore]
        public Saml20MetadataDocument metadata;

        /// <summary>
        /// Id
        /// </summary>
        [XmlAttribute(AttributeName = "id")]
        public string Id;

        /// <summary>
        /// Name
        /// </summary>
        [XmlAttribute(AttributeName = "name")]
        public string Name;

        /// <summary>
        /// Override option for the default UTF-8 encoding convention on SAML responses
        /// </summary>
        [XmlAttribute(AttributeName = "responseEncoding")]
        public string ResponseEncoding;

        /// <summary>
        /// Enable quirks mode
        /// </summary>
        [XmlAttribute(AttributeName = "QuirksMode")]
        public bool QuirksMode;

        /// <summary>
        /// Omit signature checks on assertions.
        /// </summary>
        [XmlAttribute(AttributeName = "omitAssertionSignatureCheck")]
        public bool OmitAssertionSignatureCheck;

        /// <summary>
        /// Force authentication on each authnrequest
        /// </summary>
        [XmlAttribute(AttributeName = "forceAuthn")] 
        public bool ForceAuthn;

        /// <summary>
        /// AuthnRequest is passive
        /// </summary>
        [XmlAttribute(AttributeName = "isPassive")]
        public bool IsPassive;

        /// <summary>
        /// Use default in case common domain cookie is not set, and more than one endpoint is available 
        /// </summary>
        [XmlAttribute(AttributeName = "default")]
        public bool Default;

        /// <summary>
        /// Certificate validation
        /// </summary>
        [XmlElement(ElementName = "CertificateValidation")] 
        public CertificateValidationElements CertificateValidation;

        /// <summary>
        /// AttributeQuery configuration parameters
        /// </summary>
        [XmlElement(ElementName = "AttributeQuery")] 
        public HttpBasicAuthElement AttributeQuery;

        /// <summary>
        /// ArtifactResolution configuration parameters
        /// </summary>
        [XmlElement(ElementName = "ArtifactResolution")]
        public HttpBasicAuthElement ArtifactResolution;

        /// <summary>
        /// Single sign on
        /// </summary>
        [XmlElement(ElementName = "SSO")] 
        public IDPEndPointElement SSOEndpoint;

        /// <summary>
        /// Single log off
        /// </summary>
        [XmlElement(ElementName = "SLO")]
        public IDPEndPointElement SLOEndpoint;

        /// <summary>
        /// Common Domain Cookie settings
        /// </summary>
        [XmlElement(ElementName = "CDC")] 
        public CDCElement CDC;

        /// <summary>
        /// Persistent pseudonym
        /// </summary>
        [XmlElement(ElementName = "PersistentPseudonym")] 
        public PersistentPseudonymMapper PersistentPseudonym;

        /// <summary>
        /// Get a URL that redirects the user to the login-page for this IDPEndPoint
        /// </summary>
        /// <returns></returns>
        public string GetIDPLoginUrl()
        {
            return IDPSelectionUtil.GetIDPLoginUrl(Id);
        }
    }

    /// <summary>
    /// Holds rules for certificate validation
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class CertificateValidationElements
    {
        private List<CertificateValidationElement> _elems;

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateValidationElements"/> class.
        /// </summary>
        public CertificateValidationElements()
        {
            _elems = new List<CertificateValidationElement>();
        }

        /// <summary>
        /// List certificate validation implementations
        /// </summary>
        [XmlElement(ElementName = "add")]
        public List<CertificateValidationElement> CertificateValidations;

    }

    /// <summary>
    /// A single certificate validation element
    /// </summary>
    public class CertificateValidationElement
    {
        /// <summary>
        /// The concrete type that implements the ICertificateValidationSpecification interface.
        /// </summary>
        [XmlAttribute(AttributeName = "type")]
        public string type;
    }

    /// <summary>
    /// Holds Http Basic Auth settings
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class HttpBasicAuthElement
    {
        /// <summary>
        /// Is http basic auth enabled
        /// </summary>
        [XmlAttribute(AttributeName = "enableHttpBasicAuth")]
        public bool Enabled;

        /// <summary>
        /// The username
        /// </summary>
        [XmlAttribute(AttributeName = "username")]
        public string Username;

        /// <summary>
        /// The password
        /// </summary>
        [XmlAttribute(AttributeName = "password")]
        public string Password;
    }

    /// <summary>
    /// Holds Common Domain Cookie settings
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class CDCElement
    {
        /// <summary>
        /// Extra common domain cookie settings.
        /// </summary>
        [XmlElement(ElementName = "Settings")] 
        public ExtraSettings ExtraSettings;

    }

    /// <summary>
    /// Extra key value settings for a configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class ExtraSettings
    {
        /// <summary>
        /// List of extra settings
        /// </summary>
        [XmlElement(ElementName="add")]
        public List<KeyValue> KeyValues;
    }

    /// <summary>
    /// Hold key value pairs.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class KeyValue
    {
        /// <summary>
        /// The key (name)
        /// </summary>
        [XmlAttribute(AttributeName="key")]
        public string Key;

        /// <summary>
        /// The value
        /// </summary>
        [XmlAttribute(AttributeName = "value")]
        public string Value;

    }

    /// <summary>
    /// The persistent pseudonym mapper configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class PersistentPseudonymMapper
    {
        private IPersistentPseudonymMapper _mapper = null;

        /// <summary>
        /// Mapper to use
        /// </summary>
        [XmlAttribute("mapper")] 
        public string Mapper;

        ///<summary>
        /// Returns the runtime-class configured pseudonym mapper (if any is present) for a given IdP.
        ///</summary>
        ///<returns></returns>
        public IPersistentPseudonymMapper GetMapper()
        {
            if (String.IsNullOrEmpty(Mapper))
                return null;

            if (_mapper != null)
                return _mapper;

            _mapper = (IPersistentPseudonymMapper)Activator.CreateInstance(Type.GetType(Mapper), true);
            return _mapper;
        }
    }

    /// <summary>
    /// The IDPEndPointElement configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class IDPEndPointElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IDPEndPointElement"/> class.
        /// </summary>
        public IDPEndPointElement()
        {}

        /// <summary>
        /// Constructor that converts the Saml20 Endpoint element to our IDPEndpointElement.
        /// </summary>        
        public IDPEndPointElement(Endpoint endpoint)
        {
            if (endpoint == null)
                throw new ArgumentNullException("endpoint");

            Url = endpoint.Location;
            switch(endpoint.Binding)
            {
                case Saml20Constants.ProtocolBindings.HTTP_Post :
                    Binding = SAMLBinding.POST;
                    break;
                case Saml20Constants.ProtocolBindings.HTTP_Redirect :
                    Binding = SAMLBinding.REDIRECT;
                    break;
                case Saml20Constants.ProtocolBindings.HTTP_Artifact :
                    Binding = SAMLBinding.ARTIFACT;
                    break;
                case Saml20Constants.ProtocolBindings.HTTP_SOAP :
                    Binding = SAMLBinding.SOAP;
                    break;
                default:
                    throw new InvalidOperationException("Binding not supported: " + endpoint.Binding);
            }
        }

        /// <summary>
        /// Url
        /// </summary>
        [XmlAttribute(AttributeName = "url")]
        public string Url;

        /// <summary>
        /// Binding
        /// </summary>
        [XmlAttribute(AttributeName = "binding")]
        public SAMLBinding Binding;

        /// <summary>
        /// Force a different protocol binding
        /// </summary>
        [XmlAttribute(AttributeName = "ForceProtocolBinding")]
        public string ForceProtocolBinding;

        /// <summary>
        /// Allows the caller to access the xml representation of an assertion before it's 
        /// translated to a strongly typed instance
        /// </summary>
        [XmlAttribute(AttributeName = "idpTokenAccessor")]
        public string IdpTokenAccessor;
    }

    /// <summary>
    /// Saml binding types
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    [Flags]
    public enum SAMLBinding
    {
        /// <summary>
        /// No binding set.
        /// </summary>
        NOT_SET = 0,
        /// <summary>
        /// POST binding
        /// </summary>
        POST = 1,
        /// <summary>
        /// Redirect binding
        /// </summary>
        REDIRECT = 2,
        /// <summary>
        /// Artifact binding
        /// </summary>
        ARTIFACT = 4,
        /// <summary>
        /// SOAP binding
        /// </summary>
        SOAP = 8,
    }
}
