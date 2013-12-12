using System;
using SAML2.Config;

namespace SAML2.State
{
    /// <summary>
    /// State service provider.
    /// </summary>
    public class StateServiceProvider
    {
        #region Static Fields

        /// <summary>
        /// state service provider static instance.
        /// </summary>
        private static StateServiceProvider _instance;

        #endregion

        #region Fields

        /// <summary>
        /// The state service factory.
        /// </summary>
        private readonly IStateServiceFactory _stateServiceFactory;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// Initializes static members of the <see cref="StateServiceProvider" /> class.
        /// </summary>
        static StateServiceProvider()
        {
            var stateServiceClass = Saml2Config.GetConfig().State.StateServiceFactory;
            var stateServiceFactory = string.IsNullOrEmpty(stateServiceClass) ? new SessionStateServiceFactory() : GetStateServiceFactory(stateServiceClass);
            SetStateServiceFactory(stateServiceFactory);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="StateServiceProvider" /> class.
        /// </summary>
        /// <param name="stateServiceFactory">The state service factory.</param>
        private StateServiceProvider(IStateServiceFactory stateServiceFactory)
        {
            _stateServiceFactory = stateServiceFactory;
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// Sets the state service factory.
        /// </summary>
        /// <param name="stateServiceFactory">The state service factory.</param>
        public static void SetStateServiceFactory(IStateServiceFactory stateServiceFactory)
        {
            _instance = new StateServiceProvider(stateServiceFactory);
        }

        /// <summary>
        /// Gets a state service for the specified key.
        /// </summary>
        /// <param name="keyName">Name of the key.</param>
        /// <returns>An instance of <see cref="IInternalStateService" />.</returns>
        public static IInternalStateService StateServiceFor(string keyName)
        {
            return _instance._stateServiceFactory.StateServiceFor(keyName);
        }

        /// <summary>
        /// Gets a state service for the specified type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns>An instance of <see cref="IInternalStateService" />.</returns>
        public static IInternalStateService StateServiceFor(Type type)
        {
            return _instance._stateServiceFactory.StateServiceFor(type);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Gets the state service factory.
        /// </summary>
        /// <param name="saml2StateServiceClass">The SAML2 state service class.</param>
        /// <returns>The implementation of <see cref="IStateServiceFactory" />.</returns>
        private static IStateServiceFactory GetStateServiceFactory(string saml2StateServiceClass)
        {
            IStateServiceFactory stateServiceFactory;
            var stateServiceFactoryType = Type.GetType(saml2StateServiceClass);
            try
            {
                stateServiceFactory = (IStateServiceFactory)Activator.CreateInstance(stateServiceFactoryType);
            }
            catch (MissingMethodException ex)
            {
                throw new ApplicationException("Public constructor was not found for " + stateServiceFactoryType, ex);
            }
            catch (InvalidCastException ex)
            {
                throw new ApplicationException(stateServiceFactoryType + "Type does not implement " + typeof(IStateServiceFactory), ex);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Unable to instantiate: " + stateServiceFactoryType, ex);
            }

            return stateServiceFactory;
        }

        #endregion
    }
}