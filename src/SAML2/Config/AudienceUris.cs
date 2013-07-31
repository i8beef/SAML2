using System;
using System.Collections.Generic;
using System.Xml.Serialization;
using Saml2.Properties;

namespace SAML2.Config
{
    /// <summary>
    /// Container for a list of strings (from config) that represent wellformed absolute audience uris
    /// </summary>
    public class AudienceUris
    {
        private List<string> _audiences;

        /// <summary>
        /// Gets or sets the audiences.
        /// </summary>
        /// <value>The audiences.</value>
        [XmlElement("Audience")]
        public List<string> Audiences
        {
            get { return _audiences; }
            set
            {
                ValidateUris(value);
                _audiences = value;
            }
        }

        /// <summary>
        /// Validates the wellformedness of a list of uri strings.
        /// </summary>
        /// <param name="value">The value.</param>
        private void ValidateUris(IEnumerable<string> value)
        {
            if (value == null)
                return;

            foreach (string uri in value)
            {
                if (Uri.IsWellFormedUriString(uri, UriKind.Absolute))
                    continue;

                throw new FormatException(Resources.InvalidWellformedAbsoluteUriStringFormat(uri));
            }
        }
    }
}
