using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Security;
using SAML2.config;
using SAML2.Schema.Core;
using SAML2.Identity;

namespace SAML2.identity
{
    /// <summary>
    /// <para>
    /// A specialized version of GenericIdentity that contains attributes from a SAML 2 assertion. 
    /// </para>
    /// <para>
    /// The AuthenticationType property of the Identity will be "urn:oasis:names:tc:SAML:2.0:assertion".
    /// </para>
    /// <para>
    /// The order of the attributes is not maintained when converting from the saml assertion to this class. 
    /// </para>
    /// </summary>
    [Serializable]
    public class Saml20Identity : GenericIdentity, ISaml20Identity 
    {
        private readonly Dictionary<string, List<SamlAttribute>> _attributes;
        private string _persistenPseudonym;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Identity"/> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="attributes">The attributes.</param>
        /// <param name="persistentPseudonym">The persistent pseudonym.</param>
        public Saml20Identity(string name, ICollection<SamlAttribute> attributes, string persistentPseudonym) 
            : base(name, Saml20Constants.ASSERTION)
        {
            _attributes = new Dictionary<string, List<SamlAttribute>>();

            foreach (SamlAttribute att in attributes)
            {
                if (! _attributes.ContainsKey(att.Name))
                  _attributes.Add(att.Name,new List<SamlAttribute>());
                _attributes[att.Name].Add(att);
            }
            _persistenPseudonym = persistentPseudonym;
        }

        /// <summary>
        /// <para>
        /// Retrieves the user's identity and the attributes that were extracted from the saml assertion.
        /// </para>
        /// <para>
        /// This property may return null if the initialization of the saml identity fails.
        /// </para>
        /// </summary>
        public static Saml20Identity Current
        {
            get
            {
                if (Saml20PrincipalCache.GetPrincipal() != null)
                    return Saml20PrincipalCache.GetPrincipal().Identity as Saml20Identity;
                return null;
            }
        }

        /// <summary>
        /// Check if the Saml 2 Assertion's attributes have been correctly initialized.
        /// </summary>
        public static bool IsInitialized()
        {
            return Saml20PrincipalCache.GetPrincipal() != null && Saml20PrincipalCache.GetPrincipal().Identity is Saml20Identity;
        }

        /// <summary>
        /// This method converts the received Saml assertion into a .Net principal.
        /// </summary>
        internal static IPrincipal InitSaml20Identity(Saml20Assertion assertion, IDPEndPoint point)
        {
            bool isPersistentPseudonym = assertion.Subject.Format == Saml20Constants.NameIdentifierFormats.Persistent;
            // Protocol-level support for persistent pseudonyms: If a mapper has been configured, use it here before constructing the principal.
            string subjectIdentifier = assertion.Subject.Value;
            if (isPersistentPseudonym && point.PersistentPseudonym != null)
                subjectIdentifier = point.PersistentPseudonym.GetMapper().MapIdentity(assertion.Subject);

            // Create identity
            Saml20Identity identity = new Saml20Identity(subjectIdentifier, assertion.Attributes, isPersistentPseudonym ? assertion.Subject.Value : null);                        

            return new GenericPrincipal(identity, new string[] { });
        }

        /// <summary>
        /// Retrieve an saml 20 attribute using its name. Note that this is the value contained in the 'Name' attribute, and 
        /// not the 'FriendlyName' attribute.
        /// </summary>        
        /// <exception cref="KeyNotFoundException">If the identity instance does not have the requested attribute.</exception>
        public List<SamlAttribute> this [string attributeName]
        {
            get { return _attributes[attributeName]; }
        }

        /// <summary>
        /// Check if the identity contains a certain attribute.
        /// </summary>
        /// <param name="attributeName">The name of the attribute to look for.</param>        
        public bool HasAttribute(string attributeName)
        {
            return _attributes.ContainsKey(attributeName);
        }

        /// <summary>
        /// Returns the value of the persistent pseudonym issued by the IdP if the Service Provider connection
        /// is set up with persistent pseudonyms. Otherwise, returns null.
        /// </summary>
        /// <value></value>
        public string PersistentPseudonym
        {
            get { return _persistenPseudonym; }
        }


        internal void AddAttributeFromQuery(string name, SamlAttribute value)
        {

            if (!_attributes.ContainsKey(name))
                _attributes.Add(name, new List<SamlAttribute>());
            if (!_attributes[name].Contains(value))
                _attributes[name].Add(value);

        }
                
        #region IEnumerable<Attribute> Members

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Collections.Generic.IEnumerator`1"/> that can be used to iterate through the collection.
        /// </returns>
        IEnumerator<SamlAttribute> IEnumerable<SamlAttribute>.GetEnumerator()
        {
            List<SamlAttribute> allAttributes = new List<SamlAttribute>();
            foreach (string name in _attributes.Keys)
            { allAttributes.AddRange(_attributes[name]); };
            return allAttributes.GetEnumerator();
        }

        #endregion

        #region IEnumerable Members

        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Collections.IEnumerator"/> object that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator GetEnumerator()
        {
            return ((IEnumerable<SamlAttribute>) this).GetEnumerator();
        }

        #endregion
    }
}
