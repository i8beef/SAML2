using System;
using System.Web;
using System.Web.Security;

namespace SAML2.State
{
    /// <summary>
    /// Cache based state service.
    /// </summary>
    public class CacheStateService : IInternalStateService
    {
        #region Constants

        /// <summary>
        /// SAML2 session identifier
        /// </summary>
        protected const string CookieName = "SAML2Session";

        #endregion

        #region Fields

        /// <summary>
        /// Expiry for cookie and cached data
        /// </summary>
        private readonly int _cacheExpiration;

        /// <summary>
        /// The HTTP context.
        /// </summary>
        private readonly HttpContext _context;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// Initializes a new instance of the <see cref="CacheStateService" /> class.
        /// </summary>
        /// <param name="context">The context.</param>
        public CacheStateService(HttpContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CacheStateService" /> class.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="cacheExpiration">The cache expiration minutes.</param>
        public CacheStateService(HttpContext context, string cacheExpiration) : this(context)
        {
            if (!string.IsNullOrEmpty(cacheExpiration))
            {
                int cacheExpirationMinutes;
                if (int.TryParse(cacheExpiration, out cacheExpirationMinutes))
                {
                    _cacheExpiration = cacheExpirationMinutes;
                    return;
                }
            }

            _cacheExpiration = 60;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CacheStateService" /> class.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="cacheExpiration">The cache expiration minutes.</param>
        public CacheStateService(HttpContext context, int? cacheExpiration) : this(context)
        {
            _cacheExpiration = cacheExpiration ?? 60;
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// Gets the specified key from the state store.
        /// </summary>
        /// <typeparam name="T">The expected type of the returned value.</typeparam>
        /// <param name="key">The key.</param>
        /// <returns>The value.</returns>
        public virtual T Get<T>(string key)
        {
            var value = _context.Cache[GetCacheKey(_context, key)];

            return value == null ? default(T) : (T)value;
        }

        /// <summary>
        /// Removes the specified key from the state store.
        /// </summary>
        /// <param name="key">The key.</param>
        public virtual void Remove(string key)
        {
            _context.Cache.Remove(GetCacheKey(_context, key));
        }

        /// <summary>
        /// Sets the specified key to the specified value in the state store.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        public virtual void Set(string key, object value)
        {
            _context.Cache[GetCacheKey(_context, key)] = value;
        }

        #endregion

        #region Methods

        /// <summary>
        /// Gets the cache key.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="key">The key.</param>
        /// <returns>The cache key for the specified key name.</returns>
        protected string GetCacheKey(HttpContext context, string key)
        {
            return string.Format("{0}-{1}", GetCacheKeyPrefix(context), key);
        }

        /// <summary>
        /// Gets the decrypted ticket value.
        /// </summary>
        /// <param name="encryptedTicket">The encrypted ticket.</param>
        /// <returns>The decrypted ticket value.</returns>
        private static string GetDecryptedTicketValue(string encryptedTicket)
        {
            try
            {
                var ticket = FormsAuthentication.Decrypt(encryptedTicket);
                return ticket != null ? ticket.UserData : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Gets the encrypted ticket.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="expiry">The expiry.</param>
        /// <returns>The encrypted ticket.</returns>
        private static string GetEncryptedTicket(string value, DateTime expiry)
        {
            return FormsAuthentication.Encrypt(new FormsAuthenticationTicket(1, "Ticket", DateTime.UtcNow, expiry, false, value));
        }

        /// <summary>
        /// Gets the cache key prefix.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>The cache key prefix.</returns>
        private string GetCacheKeyPrefix(HttpContext context)
        {
            var prefix = string.Empty;

            var cookie = context.Request.Cookies[CookieName];
            if (cookie != null && !string.IsNullOrEmpty(cookie.Value))
            {
                prefix = GetDecryptedTicketValue(cookie.Value);
            }

            if (string.IsNullOrEmpty(prefix))
            {
                prefix = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            }

            var expiry = DateTime.UtcNow.AddMinutes(_cacheExpiration);
            var cookieValue = GetEncryptedTicket(prefix, expiry);

            cookie = new HttpCookie(CookieName)
                         {
                             Value = cookieValue,
                             Expires = expiry
                         };

            context.Response.SetCookie(cookie);

            return prefix;
        }

        #endregion
    }
}