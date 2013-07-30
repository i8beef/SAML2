using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using SAML2.config;
using SAML2.protocol;

namespace SAML2.Utils
{
    /// <summary>
    /// This delegate is used handling events, where the framework have several configured IDP's to choose from
    /// and needs information on, which one to use.
    /// </summary>
    /// <param name="ep">List of configured endpoints</param>
    /// <returns>The IDPEndPoint for the IDP that should be used for authentication</returns>
    public delegate IDPEndPoint IDPSelectionEventHandler (IDPEndpoints ep);

    /// <summary>
    /// Contains helper functionality for selection of IDP when more than one is configured
    /// </summary>
    public class IDPSelectionUtil
    {
        /// <summary>
        /// The event handler will be called, when no Common Domain Cookie is set, 
        /// no IDPEndPoint is marked as default in the SAML20Federation configuration,
        /// and no idpSelectionUrl is configured.
        /// Make sure that only one eventhandler is added, since only the last result of the eventhandler invocation will be used.
        /// </summary>
        public static event IDPSelectionEventHandler IDPSelectionEvent;

        internal static IDPEndPoint InvokeIDPSelectionEventHandler(IDPEndpoints endpoints)
        {
            if(IDPSelectionEvent != null)
            {
                return IDPSelectionEvent(endpoints);
            }

            return null;
        }

        /// <summary>
        /// Helper method for generating URL to a link, that the user can click to select that particular IDPEndPoint for authorization.
        /// Usually not called directly, but called from IDPEndPoint.GetIDPLoginUrl()
        /// </summary>
        /// <param name="idpId">Id of IDP that an authentication URL is needed for</param>
        /// <returns>A URL that can be used for logging in at the IDP</returns>
        public static string GetIDPLoginUrl(string idpId)
        {
            return string.Format("{0}?{1}={2}", SAML20FederationConfig.GetConfig().ServiceProvider.SignOnEndpoint.localPath, Saml20SignonHandler.IDPChoiceParameterName, HttpUtility.UrlEncode(idpId));
        }
    }
}
