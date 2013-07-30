using System.Web;
using SAML2.protocol;

namespace SAML2.Actions
{
    /// <summary>
    /// An implementation of the IAction interface can be called during login and logoff of the 
    /// SAML Connector framework in order to perform a specific action.
    /// </summary>
    public interface IAction
    {
        /// <summary>
        /// Action performed during login.
        /// </summary>
        /// <param name="handler">The handler initiating the call.</param>
        /// <param name="context">The current http context.</param>
        /// <param name="assertion">The saml assertion of the currently logged in user.</param>
        void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion);

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        /// <param name="handler">The handler.</param>
        /// <param name="context">The context.</param>
        /// <param name="IdPInitiated">During IdP initiated logout some actions such as redirecting should not be performed</param>
        void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated);

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        /// <value>The name.</value>
        string Name { get; set; }
    }
}
