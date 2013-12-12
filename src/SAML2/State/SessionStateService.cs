using System.Web;

namespace SAML2.State
{
    /// <summary>
    /// Session based state service.
    /// </summary>
    public class SessionStateService : IInternalStateService
    {
        #region Fields

        /// <summary>
        /// The HTTP context.
        /// </summary>
        private readonly HttpContext _context;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionStateService" /> class.
        /// </summary>
        /// <param name="context">The context.</param>
        public SessionStateService(HttpContext context)
        {
            _context = context;
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// Gets the specified key from the state store.
        /// </summary>
        /// <typeparam name="T">The expected type of the returned value.</typeparam>
        /// <param name="key">The key.</param>
        /// <returns>The value.</returns>
        public T Get<T>(string key)
        {
            var value = _context.Session[key];

            return value == null ? default(T) : (T)value;
        }

        /// <summary>
        /// Removes the specified key from the state store.
        /// </summary>
        /// <param name="key">The key.</param>
        public void Remove(string key)
        {
            _context.Session.Remove(key);
        }

        /// <summary>
        /// Sets the specified key to the specified value in the state store.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        public void Set(string key, object value)
        {
            _context.Session[key] = value;
        }

        #endregion
    }
}