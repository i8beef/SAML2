using System.Web;

namespace SAML2.State
{
    /// <summary>
    /// Interface for internal state services.
    /// </summary>
    public interface IInternalStateService
    {
        #region Public Methods and Operators

        /// <summary>
        /// Gets the specified key from the state store.
        /// </summary>
        /// <typeparam name="T">The expected type of the returned value.</typeparam>
        /// <param name="key">The key.</param>
        /// <returns>The value.</returns>
        T Get<T>(string key);

        /// <summary>
        /// Removes the specified key from the state store.
        /// </summary>
        /// <param name="key">The key.</param>
        void Remove(string key);

        /// <summary>
        /// Sets the specified key to the specified value in the state store.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        void Set(string key, object value);

        #endregion
    }
}