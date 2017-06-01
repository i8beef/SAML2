using System;
using System.Collections.Generic;
using System.Linq;
using SAML2.Config;

namespace SAML2.Actions
{
    /// <summary>
    /// Actions helper class.
    /// </summary>
    internal class Actions
    {

        /// <summary>
        /// Gets the actions.
        /// </summary>
        /// <returns>The currently configured Action list.</returns>
        internal IList<ISignOnAction> SignOnActions
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the actions.
        /// </summary>
        /// <returns>The currently configured Action list.</returns>
        internal IList<ILogoutAction> LogoutActions
        {
            get;
            private set;
        }

        internal Actions(ActionCollection signOnActions, ActionCollection logoutActions)
        {
            var @default = GetDefaultActions();
            SignOnActions = signOnActions != null && signOnActions.Any()
                           ? signOnActions.Select(ac => (ISignOnAction)Activator.CreateInstance(Type.GetType(ac.Type))).ToList()
                           : @default as IList<ISignOnAction>;
            LogoutActions = logoutActions != null && logoutActions.Any()
                           ? signOnActions.Select(ac => (ILogoutAction)Activator.CreateInstance(Type.GetType(ac.Type))).ToList()
                           : @default as IList<ILogoutAction>;
        }

        private static List<IAction> GetDefaultActions()
        {
            return new List<IAction>
                       {
                           new SamlPrincipalAction(),
                           new FormsAuthenticationAction(),
                           new RedirectAction()
                       };
        }
    }
}
