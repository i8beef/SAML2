using System.Configuration;

namespace SAML2.Config
{
	/// <summary>
	/// State configuration element.
	/// </summary>
	public class StateElement: WritableConfigurationElement
	{
		#region Attributes

		/// <summary>
		/// Gets or sets the state service factory.
		/// </summary>
		/// <value>The logging factory.</value>
		[ConfigurationProperty( "stateServiceFactory" )]
		public string StateServiceFactory { get { return (string)base["stateServiceFactory"]; } set { base["stateServiceFactory"] = value; } }

		/// <summary>
		/// Expiry for both cookie and cache, used in the CacheStateService
		/// </summary>
		[ConfigurationProperty( "cacheExpiryMinutes" )]
		public int? CacheExpiryMinutes { get { return (int?)base["cacheExpiryMinutes"]; } set { base["cacheExpiryMinutes"] = value; } }

		/// <summary>
		/// Memcached nodes used in the MemcachedStateService. Pipe-delimited for clustered nodes
		/// </summary>
		[ConfigurationProperty( "memcachedNodes" )]
		public string MemcachedNodes { get { return (string)base["memcachedNodes"]; } set { base["memcachedNodes"] = value; } }

		#endregion
	}
}
