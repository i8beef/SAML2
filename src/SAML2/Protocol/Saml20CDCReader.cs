using System.Diagnostics;
using System.Web;
using System;
using SAML2.config;
using SAML2.Logging;
using SAML2.Properties;
using SAML2.protocol;
using Trace=SAML2.Utils.Trace;

namespace SAML2.protocol
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
                Trace.TraceMethodCalled(GetType(), "ProcessRequest()");
                SAML20FederationConfig config = ConfigurationReader.GetConfig<SAML20FederationConfig>();

                if (config == null)
                    throw new Saml20Exception("Missing SAML20Federation config section in web.config.");

                Saml20ServiceEndpoint endp
                    = config.ServiceProvider.serviceEndpoints.Find(delegate(Saml20ServiceEndpoint ep) { return ep.endpointType == EndpointType.SIGNON; });

                if (endp == null)
                    throw new Saml20Exception("Signon endpoint not found in configuration");

                string returnUrl = config.ServiceProvider.Server + endp.localPath + "?r=1";

                HttpCookie samlIdp = context.Request.Cookies[CommonDomainCookie.COMMON_DOMAIN_COOKIE_NAME];

                if (samlIdp != null)
                {
                    returnUrl += "&_saml_idp=" + HttpUtility.UrlEncode(samlIdp.Value);

                    if (Trace.ShouldTrace(TraceEventType.Information))
                        Trace.TraceData(TraceEventType.Information, string.Format(Tracing.CDC, samlIdp.Value));

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
