using System;
using System.Configuration;
using SAML2.Identity;

namespace SAML2.Config
{
    /// <summary>
    /// Persistent Pseudonym configuration element.
    /// </summary>
    public class PersistentPseudonymElement : ConfigurationElement
    {
        /// <summary>
        /// Persistent Pseudonym mapper instance.
        /// </summary>
        private IPersistentPseudonymMapper _mapper;

        #region Attributes

        /// <summary>
        /// Gets the mapper.
        /// </summary>
        [ConfigurationProperty("mapper")]
        public string Mapper
        {
            get { return (string)base["mapper"]; }
        }

        #endregion

        ///<summary>
        /// Returns the runtime-class configured pseudonym mapper (if any is present) for a given IdP.
        ///</summary>
        ///<returns></returns>
        public IPersistentPseudonymMapper GetMapper()
        {
            if (!String.IsNullOrEmpty(Mapper))
            {
                _mapper = (IPersistentPseudonymMapper)Activator.CreateInstance(Type.GetType(Mapper), true);
            }
            else
            {
                _mapper = null;
            }

            return _mapper;
        }
    }
}
