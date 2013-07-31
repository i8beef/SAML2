using System;
using System.Collections.Generic;
using System.Text;
using System.Web;

namespace SAML2.Protocol
{
    /// <summary>
    /// Implements access to the common domain cookie specified in the SAML20 indentity provider discovery profile
    /// </summary>
    public class CommonDomainCookie
    {
        /// <summary>
        /// Che name of the CDC cookie
        /// </summary>
        public const string COMMON_DOMAIN_COOKIE_NAME = "_saml_idp";

        #region Private variables

        private readonly HttpCookieCollection _cookies;

        private readonly string _saml_idp;

        private bool _isLoaded = false;

        #endregion

        #region Constructor functions

        /// <summary>
        /// Initializes a new instance of the <see cref="CommonDomainCookie"/> class.
        /// </summary>
        /// <param name="cookies">The cookies.</param>
        public CommonDomainCookie(HttpCookieCollection cookies)
        {
            _cookies = cookies;
            _knownIDPs = new List<string>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CommonDomainCookie"/> class.
        /// </summary>
        /// <param name="saml_idp">The cookie value.</param>
        public CommonDomainCookie(string saml_idp)
        {
            _saml_idp = saml_idp;
            _knownIDPs = new List<string>();
        }

        #endregion

        #region Properties

        private bool _isSet = false;

        /// <summary>
        /// Gets a value indicating whether the Common Domain Cookie was set (had valid values).
        /// </summary>
        /// <value><c>true</c> if the Common Domain Cookie is set; otherwise, <c>false</c>.</value>
        public bool IsSet
        {
            get
            {
                Load();
                return _isSet;
            }
        }

        private readonly List<string> _knownIDPs;

        /// <summary>
        /// Gets the list of known IDPs.
        /// </summary>
        /// <value>The known IDPs. Caller should check that values are valid URIs before using them as such.</value>
        public List<string> KnownIDPs
        {
            get
            {
                EnsureSet();
                return _knownIDPs;
            }
        }

        /// <summary>
        /// Gets the preferred IDP.
        /// </summary>
        /// <value>The preferred IDP. Caller should check that this value is a valid URI.</value>
        public string PreferredIDP
        {
            get
            {
                EnsureSet();

                if (_knownIDPs.Count > 0)
                    return _knownIDPs[_knownIDPs.Count - 1];

                return string.Empty;
            }
        }

        #endregion

        #region Private utility functions

        private void EnsureSet()
        {
            Load();
            if(!_isSet)
                throw new Saml20Exception("The common domain cookie is not set. Please make sure to check the IsSet property before accessing the class' properties.");
        }

        private void Load()
        {
            if (_cookies != null)
                LoadCookie();
            if (!string.IsNullOrEmpty(_saml_idp))
                LoadFromString();
        }

        private void LoadFromString()
        {
            if (!_isLoaded)
            {
                ParseCookie(_saml_idp);
                _isSet = true;
                _isLoaded = true;
            }
        }

        private void LoadCookie()
        {
            if(!_isLoaded)
            {
                HttpCookie cdc = _cookies[COMMON_DOMAIN_COOKIE_NAME];
                if(cdc != null)
                {
                    ParseCookie(cdc.Value);
                    _isSet = true;

                }
                _isLoaded = true;
            }
        }

        private void ParseCookie(string rawValue)
        {
            string value = HttpUtility.UrlDecode(rawValue);
            string[] idps = value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string base64idp in idps)
            {
                byte[] bytes = Convert.FromBase64String(base64idp);
                string idp = Encoding.ASCII.GetString(bytes);
                _knownIDPs.Add(idp);                
            }
        }

        #endregion
    }
}