using SAML2.Config;

namespace SAML2.State
{
	/// <summary>
	/// State service factory used to create a <see cref="CacheStateService"/>.
	/// </summary>
	public class CacheStateServiceFactory: IStateServiceFactory
	{
		/// <summary>
		/// Cache state service instance.
		/// </summary>
		private static readonly IInternalStateService CacheStateService = new CacheStateService( Saml2Config.GetConfig().State.CacheExpiryMinutes );

		/// <summary>
		/// Gets a state service for the specified type
		/// </summary>
		/// <param name="keyName"></param>
		/// <returns></returns>
		public IInternalStateService StateServiceFor( string keyName )
		{
			return CacheStateService;
		}

		/// <summary>
		/// Gets a state service for the specified type
		/// </summary>
		/// <param name="type"></param>
		/// <returns></returns>
		public IInternalStateService StateServiceFor( System.Type type )
		{
			return CacheStateService;
		}
	}
}


