using System;

namespace SAML2.Exceptions
{
    /// <summary>
    /// This exception is thrown to indicate an error in the SAML2 configuration.
    /// </summary>
    public class Saml20ConfigurationException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20ConfigurationException"/> class.
        /// </summary>
        public Saml20ConfigurationException() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20ConfigurationException"/> class.
        /// </summary>
        /// <param name="msg">The MSG.</param>
        public Saml20ConfigurationException(string msg) : base(msg) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20ConfigurationException"/> class.
        /// </summary>
        /// <param name="msg">A message describing the problem that caused the exception.</param>
        /// <param name="cause">Another exception that may be related to the problem.</param>
        public Saml20ConfigurationException(string msg, Exception cause) : base(msg, cause) { }
    }
}
