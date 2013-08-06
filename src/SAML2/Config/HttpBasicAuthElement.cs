using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Http Basic Auth comfiguration element.
    /// </summary>
    public class HttpBasicAuthElement : ConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets a value indicating whether this <see cref="HttpBasicAuthElement"/> is enabled.
        /// </summary>
        [ConfigurationProperty("enableHttpBasicAuth")]
        public bool Enabled
        {
            get { return (bool)base["enableHttpBasicAuth"]; }
        }

        /// <summary>
        /// Gets the username.
        /// </summary>
        [ConfigurationProperty("username")]
        public string Username
        {
            get { return (string)base["username"]; }
        }

        /// <summary>
        /// Gets the password.
        /// </summary>
        [ConfigurationProperty("password")]
        public string Password
        {
            get { return (string)base["password"]; }
        }

        #endregion
    }
}
