using System.Collections.Generic;
using System.Security.Principal;
using SAML2.Schema.Core;

namespace SAML2.identity
{
    /// <summary>
    /// The SAML 2.0 extension to the <c>IIdentity</c> interface.
    /// </summary>
    public interface ISaml20Identity : IEnumerable<SamlAttribute>, IIdentity 
    {
        /// <summary>
        /// Retrieve an saml 20 attribute using its name. Note that this is the value contained in the 'Name' attribute, and 
        /// not the 'FriendlyName' attribute.
        /// </summary>        
        /// <exception cref="KeyNotFoundException">If the identity instance does not have the requested attribute.</exception>
        List<SamlAttribute> this[string attributeName] { get; }

        /// <summary>
        /// Check if the identity contains a certain attribute.
        /// </summary>
        /// <param name="attributeName">The name of the attribute to look for.</param>        
        bool HasAttribute(string attributeName);

        /// <summary>
        /// Returns the value of the persistent pseudonym issued by the IdP if the Service Provider connection 
        /// is set up with persistent pseudonyms. Otherwise, returns null.
        /// </summary>
        string PersistentPseudonym { get; }
    }
}