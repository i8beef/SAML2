using System.Collections.Generic;
using System.Linq;
using SAML2.Config;
using System;

namespace SAML2.Actions
{
    /// <summary>
    /// Actions helper class.
    /// </summary>
    public class Actions
    {
        /// <summary>
        /// Gets the default actions. 
        /// </summary>
        /// <returns>The system default actions.</returns>
        public static List<IAction> GetDefaultActions()
        {
            return new List<IAction>
                       {
                           new SamlPrincipalAction(),
                           new FormsAuthenticationAction(),
                           new RedirectAction()
                       };
        }

        /// <summary>
        /// Gets the actions.
        /// </summary>
        /// <returns>The currently configured Action list.</returns>
        public static List<IAction> GetActions()
        {
            var config = Saml2Config.GetConfig();

            return config.Actions == null
                       ? GetDefaultActions()
                       : config.Actions.Select(ac => (IAction) Activator.CreateInstance(Type.GetType(ac.Type))).ToList();
        }
    }
}
