using System.Web;

namespace SAML2.State
{
	public class SessionStateService: IInternalStateService
	{
		public T Get<T>( HttpContext context, string key )
		{
			var value = context.Session[key];

			return value == null ? default( T ) : (T)value;
		}

		public void Set( HttpContext context, string key, object value )
		{
			context.Session[key] = value;
		}

		public void Remove( HttpContext context, string key )
		{
			context.Session.Remove( key );
		}
	}
}
