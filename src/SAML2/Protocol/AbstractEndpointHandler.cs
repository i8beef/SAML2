using System;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.SessionState;
using SAML2.Config;
using SAML2.Logging;
using SAML2.Protocol.Pages;

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
        /// Gets or sets the error handling behavior.
        /// </summary>
        /// <value>The error handling behavior.</value>
        public string ErrorBehavior { get; set; }

        /// <summary>
        /// Gets or sets the redirect URL.
        /// </summary>
        /// <value>The redirect URL.</value>
        public string RedirectUrl { get; set; }

        /// <summary>
        /// Displays an error page.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        /// <param name="errorMessage">The error message.</param>
        public void HandleError(HttpContext context, string errorMessage)
        {
            HandleError(context, errorMessage, false);
        }

        /// <summary>
        /// Displays an error page.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        /// <param name="errorMessage">The error message.</param>
        /// <param name="overrideConfigSetting">if set to <c>true</c> [override config setting].</param>
        public void HandleError(HttpContext context, string errorMessage, bool overrideConfigSetting)
        {
            var showError = Saml2Config.GetConfig().ShowError;
            const string defaultMessage = "Unable to validate SAML message!";

            if (!string.IsNullOrEmpty(ErrorBehavior) && ErrorBehavior.Equals(Config.ErrorBehavior.ThrowException.ToString()))
            {
                if (showError)
                {
                    throw new Saml20Exception(errorMessage);
                }
                else
                {
                    throw new Saml20Exception(defaultMessage);
                }
            }
            else
            {
                var page = new ErrorPage
                               {
                                   OverrideConfig = overrideConfigSetting,
                                   ErrorText = showError ? errorMessage : defaultMessage
                               };
                page.ProcessRequest(context);
                context.Response.End();
            }
        }

        /// <summary>
        /// Displays an error page.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        /// <param name="e">The exception that caused the error.</param>
        public void HandleError(HttpContext context, Exception e)
        {
            // ThreadAbortException is just part of ASP.NET's slightly broken conditional logic, so don't react to it.
            if (e is ThreadAbortException)
            {
                return;
            }

            var sb = new StringBuilder(1000);            
            while (e != null)
            {
                sb.AppendLine(e.ToString());                
                e = e.InnerException;                
            }

            HandleError(context, sb.ToString());
        }

        /// <summary>
        /// Redirects the user.
        /// </summary>
        /// <param name="context">The context.</param>
        public void DoRedirect(HttpContext context)
        {
            var redirectUrl = (string)context.Session["RedirectUrl"];
            if (!string.IsNullOrEmpty(redirectUrl))
            {
                context.Session.Remove("RedirectUrl");
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
    }
}