using System;
using System.Collections.Generic;
using System.Linq;
using SAML2.Config;

namespace SAML2.Actions
{
    /// <summary>
    /// Actions helper class.
    /// </summary>
    internal static class ActionsHelper
    {
        internal static IList<ISignOnAction> GetSignOnActions(ActionCollection actionCollection)
        {
            return GetActions(actionCollection) as IList<ISignOnAction>;
        }

        internal static IList<ILogoutAction> GetLogoutActions(ActionCollection actionCollection)
        {
            return GetActions(actionCollection) as IList<ILogoutAction>;
        }

        private static IList<IAction> GetActions(ActionCollection actionCollection)
        {
            return actionCollection != null && actionCollection.Any()
                           ? actionCollection.Select(ac => (IAction)Activator.CreateInstance(Type.GetType(ac.Type))).ToList()
                           : GetDefaultActions();
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
