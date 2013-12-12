using System.Configuration;

namespace SAML2.Config
{
    /// <summary>
    /// State setting collection configuration collection.
    /// </summary>
    [ConfigurationCollection(typeof(ActionElement), CollectionType = ConfigurationElementCollectionType.AddRemoveClearMap)]
    public class StateSettingCollection : EnumerableConfigurationElementCollection<StateSettingElement>
    {
    }
}