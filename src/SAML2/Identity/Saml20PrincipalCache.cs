using System.Web;
using System.Security.Principal;
using SAML2.Identity;

namespace SAML2.Identity
{
    /// <summary>
    /// 
    /// </summary>
    internal class Saml20PrincipalCache
    {
        /// <summary>
        /// Adds the principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        internal static void AddPrincipal(IPrincipal principal)
        {
            HttpContext.Current.Session[typeof (Saml20Identity).FullName] = principal;
        }

        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns></returns>
        internal static IPrincipal GetPrincipal()
        {
            return HttpContext.Current.Session[typeof(Saml20Identity).FullName] as GenericPrincipal;
        }

        /// <summary>
        /// Clears this instance.
        /// </summary>
        internal static void Clear()
        {
            HttpContext.Current.Session.Remove(typeof(Saml20Identity).FullName);
        }
    }
}
