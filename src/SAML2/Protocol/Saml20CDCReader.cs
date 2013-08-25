using System;
using System.Linq;
using System.Web;
using SAML2.Config;
using SAML2.Properties;

namespace SAML2.Protocol
{
    /// <summary>
    /// Common Domain Cookie reader endpoint
    /// </summary>
    public class Saml20CDCReader : AbstractEndpointHandler
    {
        /// <summary>
        /// Enables processing of HTTP Web requests by a custom HttpHandler that implements the <see cref="T:System.Web.IHttpHandler"/> interface.
        /// </summary>
        /// <param name="context">An <see cref="T:System.Web.HttpContext"/> object that provides references to the intrinsic server objects (for example, Request, Response, Session, and Server) used to service HTTP requests.</param>
        public override void ProcessRequest(HttpContext context)
        {
            try
            {
                Logger.DebugFormat("{0}.{1} called", GetType(), "ProcessRequest()");

                var config = Saml2Config.GetConfig();
                if (config == null)
                {
                    throw new Saml20Exception("Missing saml2 config section in web.config.");
                }

                var endp = config.ServiceProvider.Endpoints.FirstOrDefault(ep => ep.Type == EndpointType.SignOn);
                if (endp == null)
                {
                    throw new Saml20Exception("Signon endpoint not found in configuration");
                }

                var returnUrl = config.ServiceProvider.Server + endp.LocalPath + "?r=1";

                var samlIdp = context.Request.Cookies[CommonDomainCookie.CommonDomainCookieName];
                if (samlIdp != null)
                {
                    returnUrl += "&_saml_idp=" + HttpUtility.UrlEncode(samlIdp.Value);

                    Logger.DebugFormat(Tracing.CDC, samlIdp.Value);
                    Logger.Debug("Redirection to Signon endpoint found in Common Domain Cookie: " + samlIdp.Value);
                }
                else
                {
                    Logger.Debug("Redirection to Signon endpoint, no Common Domain Cookie found: " + returnUrl);
                }

                context.Response.Redirect(returnUrl);
            }
            catch (Exception ex)
            {
                HandleError(context, ex);
            }
        }
    }
}
