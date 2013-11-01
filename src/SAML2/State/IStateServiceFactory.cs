namespace SAML2.State
{
	/// <summary>
	/// Interface for all state service factory implementations.
	/// </summary>
	public interface IStateServiceFactory
	{
		/// <summary>
		/// Gets a state service for the specified name.
		/// </summary>
		/// <param name="keyName">Name of the key.</param>
		/// <returns>An <see cref="IStateServiceFactory"/> implementation.</returns>
		IInternalStateService StateServiceFor( string keyName );

		/// <summary>
		/// Gets a state service for specified type.
		/// </summary>
		/// <param name="type">The type.</param>
		/// <returns>An <see cref="IStateServiceFactory"/> implementation.</returns>
		IInternalStateService StateServiceFor( System.Type type );
	}
}
