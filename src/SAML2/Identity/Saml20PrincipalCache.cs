using System.Reflection;
using System.Security.Principal;
using SAML2.State;

namespace SAML2.Identity
{
    /// <summary>
    /// The Principal cache for SAML2.
    /// </summary>
    internal class Saml20PrincipalCache
    {
        /// <summary>
        /// State service instance
        /// </summary>
        private static readonly IInternalStateService StateService = StateServiceProvider.StateServiceFor(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Adds the principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        internal static void AddPrincipal(IPrincipal principal)
        {
            StateService.Set(typeof(Saml20Identity).FullName, principal);
        }

        /// <summary>
        /// Clears this instance.
        /// </summary>
        internal static void Clear()
        {
            StateService.Remove(typeof(Saml20Identity).FullName);
        }

        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns>The <see cref="IPrincipal"/>.</returns>
        internal static IPrincipal GetPrincipal()
        {
            return StateService.Get<GenericPrincipal>(typeof(Saml20Identity).FullName);
        }
    }
}
