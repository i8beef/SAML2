using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// Http Basic Authentication configuration element.
    /// </summary>
    public class HttpBasicAuthElement : WritableConfigurationElement
    {
        #region Attributes

        /// <summary>
        /// Gets or sets a value indicating whether <c>HttpBasicAuth</c> is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        [ConfigurationProperty("enableHttpBasicAuth")]
        public bool Enabled
        {
            get { return (bool)base["enableHttpBasicAuth"]; }
            set { base["enableHttpBasicAuth"] = value; }
        }

        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        /// <value>The username.</value>
        [ConfigurationProperty("username")]
        public string Username
        {
            get { return (string)base["username"]; }
            set { base["username"] = value; }
        }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <value>The password.</value>
        [ConfigurationProperty("password")]
        public string Password
        {
            get { return (string)base["password"]; }
            set { base["password"] = value; }
        }

        #endregion
    }
}
