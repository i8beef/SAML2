using System.Web;
using System.Web.Security;
using SAML2.Identity;
using SAML2.Protocol;
using System.Security.Principal;
using SAML2.Identity;

namespace SAML2.Actions
{
    /// <summary>
    /// Sets the SamlPrincipal on the current http context
    /// </summary>
    public class SamlPrincipalAction : IAction
    {

        /// <summary>
        /// The default action name
        /// </summary>
        public const string ACTION_NAME = "SetSamlPrincipal";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        /// <param name="handler">The handler initiating the call.</param>
        /// <param name="context">The current http context.</param>
        /// <param name="assertion">The saml assertion of the currently logged in user.</param>
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            Saml20SignonHandler signonhandler = (Saml20SignonHandler)handler;
            IPrincipal prince = Saml20Identity.InitSaml20Identity(assertion, signonhandler.RetrieveIDPConfiguration((string)context.Session[Saml20AbstractEndpointHandler.IDPTempSessionKey]));

            Saml20PrincipalCache.AddPrincipal(prince);

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
            Saml20PrincipalCache.Clear();
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
