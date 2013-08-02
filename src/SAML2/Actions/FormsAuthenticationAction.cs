using System.Web;
using System.Web.Security;
using SAML2.Identity;
using SAML2.Protocol;

namespace SAML2.Actions
{
    /// <summary>
    /// Handles setting Forms Authentication cookies.
    /// </summary>
    public class FormsAuthenticationAction : IAction
    {

        /// <summary>
        /// The default action name
        /// </summary>
        public const string ACTION_NAME = "FormsAuthentication";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        /// <param name="handler">The handler initiating the call.</param>
        /// <param name="context">The current http context.</param>
        /// <param name="assertion">The saml assertion of the currently logged in user.</param>
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            var prince = Saml20PrincipalCache.GetPrincipal();
            FormsAuthentication.SetAuthCookie(prince.Identity.Name, false);  
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        /// <param name="handler">The handler.</param>
        /// <param name="context">The context.</param>
        /// <param name="IdPInitiated">During IdP initiated logout some actions such as redirecting should not be performed</param>
        public void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            FormsAuthentication.SignOut();
        }

        private string _name;

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        /// <value>The name.</value>
        public string Name
        {
            get
            {
                return string.IsNullOrEmpty(_name) ? ACTION_NAME : _name;
            }
            set { _name = value; }
        }
    }
}
