using System;
using System.Xml.Serialization;

namespace SAML2.Config
{
    /// <summary>
    /// Common federation parameters container - used by federation initiators to populate the intended audiences in a saml assertion
    /// and by federation receivers to validate the incoming saml assertions intended audiences against the list of configured 
    /// allowed audiences
    /// </summary>
    [Serializable]
    [XmlType(AnonymousType = true)]
    [XmlRoot(ConfigurationConstants.SectionNames.Federation, IsNullable = false)]
    public class FederationConfig : ConfigurationInstance<FederationConfig>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FederationConfig"/> class.
        /// </summary>
        public FederationConfig()
        {
            SigningCertificate = new Certificate();
        }

        // To create a new XSD Run this command:
        // xsd -t:Safewhere.Config.Federation   Safewhere.dll
        /// <summary>
        /// Certificate used to sign exchanged saml tokens
        /// </summary>
        [XmlElement] 
        public Certificate SigningCertificate;
        
        /// <summary>
        /// The list of audience uris that are allowed by a receiver
        /// </summary>
        public AudienceUris AllowedAudienceUris;

        /// <summary>
        /// The list of intended audience uris
        /// </summary>
        public AudienceUris IntendedAudienceUris;

        /// <summary>
        /// The list of trusted issuers - each represented by an X509 certificate reference
        /// </summary>
        [XmlArrayItem("TrustedIssuers", IsNullable = false)]
        public Certificate[] TrustedIssuers;

        private ActionsConfig _actions;

        /// <summary>
        /// Gets the actions.
        /// </summary>
        /// <value>The actions.</value>
        [XmlElement]
        public ActionsConfig Actions
        {
            get
            {
                if(_actions == null)
                {
                    _actions = new ActionsConfig();
                }
                return _actions;
            }
            set { _actions = value; }
        }
    }

    /// <summary>
    /// The Actions configuration element class
    /// </summary>
    [Serializable]
    public class ActionsConfig
    {
        private ActionConfigAbstract[] _actionList;

        /// <summary>
        /// Gets the list of config actions.
        /// </summary>
        /// <value>The list of actions</value>
        [XmlElement("add", typeof(ActionConfigAdd))]
        [XmlElement("remove", typeof(ActionConfigRemove))]
        [XmlElement("clear", typeof(ActionConfigClear))]
        public ActionConfigAbstract[] ActionList
        {
            get { return _actionList ?? new ActionConfigAbstract[]{}; }
            set { _actionList = value; }
        }
    }

    /// <summary>
    /// Base class for config actions
    /// </summary>
    [Serializable]
    public class ActionConfigAbstract
    {
        private string _name;

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        [XmlAttribute("name")]
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        } 
    }

    /// <summary>
    /// Represents an &lt;add&gt; tag
    /// </summary>
    [Serializable]
    public class ActionConfigAdd : ActionConfigAbstract
    {
        private string _type;

        /// <summary>
        /// Gets or sets the type of a class that implements the IAction interface.
        /// </summary>
        /// <value>The type.</value>
        [XmlAttribute("type")]
        public string Type
        {
            get { return _type; }
            set { _type = value; }
        }
    }

    /// <summary>
    /// Represents a &lt;clear&gt; tag
    /// </summary>
    [Serializable]
    public class ActionConfigClear : ActionConfigAbstract
    {
        
    }

    /// <summary>
    /// Represents a &lt;remove&gt; tag
    /// </summary>
    [Serializable]
    public class ActionConfigRemove : ActionConfigAbstract
    {
        
    }

}
