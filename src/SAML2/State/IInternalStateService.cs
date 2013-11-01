using System.Web;

namespace SAML2.State
{
	public interface IInternalStateService
	{
		T Get<T>( HttpContext context, string key );

		void Set( HttpContext context, string key, object value );

		void Remove( HttpContext context, string key );
	}
}
