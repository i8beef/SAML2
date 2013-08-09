namespace SAML2.Config
{
    /// <summary>
    /// Endpoint types (signon, logout or metadata)
    /// </summary>
    public enum EndpointType
    {
        /// <summary>
        /// Signon endpoint
        /// </summary>
        SignOn,

        /// <summary>
        /// Logout endpoint
        /// </summary>
        Logout,

        /// <summary>
        /// Metadata endpoint
        /// </summary>
        Metadata
    }
}
