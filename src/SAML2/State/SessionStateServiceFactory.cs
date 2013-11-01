namespace SAML2.State
{
	/// <summary>
	/// State service factory used to create a <see cref="SessionStateService"/>.
	/// </summary>
	public class SessionStateServiceFactory: IStateServiceFactory
	{
		/// <summary>
		/// Session state service instance.
		/// </summary>
		private static readonly IInternalStateService SessionStateService = new SessionStateService();

		/// <summary>
		/// Gets a state service for the specified type
		/// </summary>
		/// <param name="keyName"></param>
		/// <returns></returns>
		public IInternalStateService StateServiceFor( string keyName )
		{
			return SessionStateService;
		}

		/// <summary>
		/// Gets a state service for the specified type
		/// </summary>
		/// <param name="type"></param>
		/// <returns></returns>
		public IInternalStateService StateServiceFor( System.Type type )
		{
			return SessionStateService;
		}
	}
}


