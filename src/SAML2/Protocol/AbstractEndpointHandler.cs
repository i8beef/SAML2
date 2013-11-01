using System.Reflection;
using System.Web;
using System.Web.SessionState;
using SAML2.Logging;
using SAML2.State;

namespace SAML2.Protocol
{
    /// <summary>
    /// A base class for all endpoint handlers.
    /// </summary>
    public abstract class AbstractEndpointHandler : IHttpHandler, IRequiresSessionState
    {
        /// <summary>
        /// Logger instance.
        /// </summary>
        protected static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(MethodBase.GetCurrentMethod().DeclaringType);

		/// <summary>
		/// State Service instance
		/// </summary>
	    protected static readonly IInternalStateService StateService = StateServiceProvider.StateServiceFor( MethodBase.GetCurrentMethod().DeclaringType );

        /// <summary>
        /// Gets or sets the redirect URL.
        /// </summary>
        /// <value>The redirect URL.</value>
        public string RedirectUrl { get; set; }

        #region IHttpHandler Members

        /// <summary>
        /// Gets a value indicating whether another request can use the <see cref="T:System.Web.IHttpHandler"/> instance.
        /// </summary>
        /// <value></value>
        /// <returns>true if the <see cref="T:System.Web.IHttpHandler"/> instance is reusable; otherwise, false.</returns>
        public bool IsReusable
        {
            get { return true; }
        }

        /// <summary>
        /// Enables processing of HTTP Web requests by a custom HttpHandler that implements the <see cref="T:System.Web.IHttpHandler"/> interface.
        /// </summary>
        /// <param name="context">An <see cref="T:System.Web.HttpContext"/> object that provides references to the intrinsic server objects (for example, Request, Response, Session, and Server) used to service HTTP requests.</param>
        public abstract void ProcessRequest(HttpContext context);

        #endregion

        /// <summary>
        /// Redirects the user.
        /// </summary>
        /// <param name="context">The context.</param>
        public void DoRedirect(HttpContext context)
        {
	        var redirectUrl = StateService.Get<string>( context, "RedirectUrl" );
            if (!string.IsNullOrEmpty(redirectUrl))
            {
				StateService.Remove(context, "RedirectUrl");
                context.Response.Redirect(redirectUrl);
            }
            else if (string.IsNullOrEmpty(RedirectUrl))
            {
                context.Response.Redirect("~/");
            }
            else
            {
                context.Response.Redirect(RedirectUrl);
            }
        }
    }
}