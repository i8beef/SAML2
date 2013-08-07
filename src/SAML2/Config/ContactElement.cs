using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Contact configuration element.
    /// </summary>
    public class ContactElement : ConfigurationElement, IConfigurationElementCollectionElement
    {
        #region Attributes

        /// <summary>
        /// Gets the company.
        /// </summary>
        [ConfigurationProperty("company")]
        public string Company
        {
            get { return (string)base["company"]; }
        }

        /// <summary>
        /// Gets the email.
        /// </summary>
        [ConfigurationProperty("email")]
        public string Email
        {
            get { return (string)base["email"]; }
        }

        /// <summary>
        /// Gets the given name.
        /// </summary>
        [ConfigurationProperty("givenName")]
        public string GivenName
        {
            get { return (string)base["givenName"]; }
        }

        /// <summary>
        /// Gets the phone.
        /// </summary>
        [ConfigurationProperty("phone")]
        public string Phone
        {
            get { return (string)base["phone"]; }
        }

        /// <summary>
        /// Gets the surname.
        /// </summary>
        [ConfigurationProperty("surName")]
        public string SurName
        {
            get { return (string)base["surName"]; }
        }

        /// <summary>
        /// Gets the type.
        /// </summary>
        [ConfigurationProperty("type", IsKey = true, IsRequired = true)]
        public ContactType Type
        {
            get { return (ContactType)base["type"]; }
        }

        #endregion

        #region Implementation of IConfigurationElementCollectionElement

        /// <summary>
        /// Gets the element key.
        /// </summary>
        public object ElementKey
        {
            get { return Type; }
        }

        #endregion
    }
}
