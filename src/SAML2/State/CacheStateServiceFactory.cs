using System;
using SAML2.Config;

namespace SAML2.State
{
    /// <summary>
    /// State service factory used to create a <see cref="CacheStateService" />.
    /// </summary>
    public class CacheStateServiceFactory : IStateServiceFactory
    {
        #region Static Fields

        /// <summary>
        /// Cache state service instance.
        /// </summary>
        private static readonly IInternalStateService CacheStateService = new CacheStateService(Saml2Config.Current.State.Settings.ContainsKey("cacheExpiration") ? Saml2Config.Current.State.Settings["cacheExpiration"] : null);

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// Gets a state service for the specified name.
        /// </summary>
        /// <param name="keyName">Name of the key.</param>
        /// <returns>An <see cref="IStateServiceFactory" /> implementation.</returns>
        public IInternalStateService StateServiceFor(string keyName)
        {
            return CacheStateService;
        }

        /// <summary>
        /// Gets a state service for specified type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns>An <see cref="IStateServiceFactory" /> implementation.</returns>
        public IInternalStateService StateServiceFor(Type type)
        {
            return CacheStateService;
        }

        #endregion
    }
}