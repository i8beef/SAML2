using System;
using System.Web;
using System.Web.Security;

namespace SAML2.State
{
	public class CacheStateService: IInternalStateService
	{
		/// <summary>
		/// SAML2 session identifier
		/// </summary>
		protected const string CookieName = "SAML2Session";

		/// <summary>
		/// Expiry for cookie and cached data
		/// </summary>
		protected readonly int ExpiryMinutes;

		public CacheStateService( int? expiryMinutes )
		{
			ExpiryMinutes = expiryMinutes ?? 60;
		}

		/// <summary>
		/// Return an encrypted ticket for storage in the cookie
		/// </summary>
		/// <param name="value"></param>
		/// <param name="expiry"></param>
		/// <returns></returns>
		private static string GetEncryptedTicket( string value, DateTime expiry )
		{
			return FormsAuthentication.Encrypt( new FormsAuthenticationTicket( 1, "Ticket", DateTime.UtcNow, expiry, false, value ) );
		}

		/// <summary>
		/// Decrypt the cookie value for use as a cache key prefix
		/// </summary>
		/// <param name="encryptedTicket"></param>
		/// <returns></returns>
		private static string GetDecryptedTicketValue( string encryptedTicket )
		{
			try
			{
				var ticket = FormsAuthentication.Decrypt( encryptedTicket );
				return ticket != null ? ticket.UserData : null;
			}
			catch
			{
				return null;
			}
		}

		/// <summary>
		/// Return and/or build the cache key prefix
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		private string GetCacheKeyPrefix( HttpContext context )
		{
			var prefix = string.Empty;

			var cookie = context.Request.Cookies[CookieName];
			if( cookie != null && !string.IsNullOrEmpty( cookie.Value ) )
			{
				prefix = GetDecryptedTicketValue( cookie.Value );
			}

			if( string.IsNullOrEmpty( prefix ) )
			{
				prefix = Guid.NewGuid().ToString( "N" ) + Guid.NewGuid().ToString( "N" ) + Guid.NewGuid().ToString( "N" );
			}

			var expiry = DateTime.UtcNow.AddMinutes( ExpiryMinutes );
			var cookieValue = GetEncryptedTicket( prefix, expiry );

			cookie = new HttpCookie( CookieName )
			{
				Value = cookieValue,
				Expires = expiry
			};

			context.Response.SetCookie( cookie );

			return prefix;
		}

		/// <summary>
		/// Builds the full cache key
		/// </summary>
		/// <param name="context"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		protected string GetCacheKey( HttpContext context, string key )
		{
			return string.Format( "{0}-{1}", GetCacheKeyPrefix( context ), key );
		}

		/// <summary>
		/// Get an item from the cache
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public virtual T Get<T>( HttpContext context, string key )
		{
			var value = context.Cache[GetCacheKey( context, key )];

			return value == null ? default( T ) : (T)value;
		}

		/// <summary>
		/// Set an item to the cache
		/// </summary>
		/// <param name="context"></param>
		/// <param name="key"></param>
		/// <param name="value"></param>
		public virtual void Set( HttpContext context, string key, object value )
		{
			context.Cache[GetCacheKey( context, key )] = value;
		}

		/// <summary>
		/// Remove item from the cache
		/// </summary>
		/// <param name="context"></param>
		/// <param name="key"></param>
		public virtual void Remove( HttpContext context, string key )
		{
			context.Cache.Remove( GetCacheKey( context, key ) );
		}
	}
}
