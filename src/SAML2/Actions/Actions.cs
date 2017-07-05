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
            return GetActions<ISignOnAction>(actionCollection);
        }

        internal static IList<ILogoutAction> GetLogoutActions(ActionCollection actionCollection)
        {
            return GetActions<ILogoutAction>(actionCollection);
        }

        private static IList<T> GetActions<T>(ActionCollection actionCollection)
        {
            return actionCollection != null && actionCollection.Any()
                           ? actionCollection.Select(ac => (T)Activator.CreateInstance(Type.GetType(ac.Type))).ToList()
                           : GetDefaultActions() as IList<T>;
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
