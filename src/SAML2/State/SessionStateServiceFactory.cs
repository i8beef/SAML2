using System;
using System.Web;

namespace SAML2.State
{
    /// <summary>
    /// State service factory used to create a <see cref="SessionStateService" />.
    /// </summary>
    public class SessionStateServiceFactory : IStateServiceFactory
    {
        #region Static Fields

        /// <summary>
        /// Session state service instance.
        /// </summary>
        private static readonly IInternalStateService SessionStateService = new SessionStateService(HttpContext.Current);

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// Gets a state service for the specified name.
        /// </summary>
        /// <param name="keyName">Name of the key.</param>
        /// <returns>An <see cref="IStateServiceFactory" /> implementation.</returns>
        public IInternalStateService StateServiceFor(string keyName)
        {
            return SessionStateService;
        }

        /// <summary>
        /// Gets a state service for specified type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns>An <see cref="IStateServiceFactory" /> implementation.</returns>
        public IInternalStateService StateServiceFor(Type type)
        {
            return SessionStateService;
        }

        #endregion
    }
}