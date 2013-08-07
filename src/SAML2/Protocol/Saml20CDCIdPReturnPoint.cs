using System;
using System.Linq;
using System.Web;
using SAML2.Config;
using SAML2.Protocol;
using SAML2.Utils;

namespace SAML2.Protocol
{
    /// <summary>
    /// 
    /// </summary>
    public class Saml20CDCIdPReturnPoint : AbstractEndpointHandler
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
                    throw new Saml20Exception("Missing SAML20Federation config section in web.config.");

                var endp = config.ServiceProvider.Endpoints.FirstOrDefault(ep => ep.Type == EndpointType.SignOn);

                if (endp == null)
                    throw new Saml20Exception("Signon endpoint not found in configuration");

                string redirectUrl = (string)context.Session["RedirectUrl"];

                if (!string.IsNullOrEmpty(redirectUrl))
                {
                    context.Session.Remove("RedirectUrl");
                    context.Response.Redirect(redirectUrl);
                }
                else if (string.IsNullOrEmpty(endp.RedirectUrl))
                {
                    context.Response.Redirect("~/");
                }
                else
                {
                    context.Response.Redirect(endp.RedirectUrl);
                }
            }
            catch (Exception ex)
            {
                HandleError(context, ex);
            }
        }
    }
}
