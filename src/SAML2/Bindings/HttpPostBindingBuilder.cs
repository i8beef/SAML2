using System;
using System.Text;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using SAML2.config;

namespace SAML2.Bindings
{
    /// <summary>
    /// Implementation of the HTTP POST binding.
    /// </summary>
    public class HttpPostBindingBuilder
    {
        #region Private variables

        /// <summary>
        /// The endpoint to send the message to.
        /// </summary>
        private IDPEndPointElement _destinationEndpoint;

        #endregion

        #region Constructor functions

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpPostBindingBuilder"/> class.
        /// </summary>
        /// <param name="endpoint">The IdP endpoint that messages will be sent to.</param>
        public HttpPostBindingBuilder(IDPEndPointElement endpoint) 
        {
            _destinationEndpoint = endpoint;
            _action = SAMLAction.SAMLRequest;
            _relayState = string.Empty;
        }
               
        #endregion

        #region Properties

        private SAMLAction _action;

        /// <summary>
        /// Gets or sets the action.
        /// </summary>
        /// <value>The action.</value>
        public SAMLAction Action
        {
            get { return _action; }
            set { _action = value; }
        }

        private string _relayState;

        /// <summary>
        /// Gets or sets the relaystate
        /// </summary>
        /// <value>The relaystate.</value>
        public string RelayState
        {
            get { return _relayState; }
            set { _relayState = value; }
        }        

        private string _request;

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        /// <value>The request.</value>
        public string Request
        {
            get { return _request; }
            set
            {
                if (!string.IsNullOrEmpty(_response))
                    throw new ArgumentException("Response property is already specified. Unable to set Request property.");
                _request = value;
            }
        }

        private string _response;

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        /// <value>The response.</value>
        public string Response
        {
            get { return _response; }
            set
            {
                if (!string.IsNullOrEmpty(_request))                                    
                    throw new ArgumentException("Request property is already specified. Unable to set Response property.");

                _response = value;
            }
        }        
        
        #endregion

        #region Page related functions

        /// <summary>
        /// Gets the ASP.Net page that will serve html to user agent.
        /// </summary>
        /// <returns></returns>
        public Page GetPage()
        {
            if (_request == null && _response == null)
                throw new InvalidOperationException("A response or request message MUST be specified before generating the page.");

            string msg = _request ?? _response;

            Page p = new Page();
            p.EnableViewState = false;
            p.EnableViewStateMac = false;

            p.Controls.Add(new LiteralControl("<?xml version=\"1.0\" encoding=\"utf-8\"?>" + Environment.NewLine));
            p.Controls.Add(new LiteralControl("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">" + Environment.NewLine));
            
            HtmlHead head = new HtmlHead();
            head.Title = "SAML2.0 POST binding";
            p.Controls.Add(head);            

            p.Controls.Add(new LiteralControl(Environment.NewLine + "<body onload=\"document.forms[0].submit()\">" + Environment.NewLine));
            p.Controls.Add(new LiteralControl("<noscript><p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.</p></noscript>"));                                   

            p.Controls.Add(new LiteralControl("<form action=\"" + _destinationEndpoint.Url + "\" method=\"post\"><div>"));

            if(!string.IsNullOrEmpty(RelayState))
            {
                HtmlInputHidden relayStateHidden = new HtmlInputHidden();
                relayStateHidden.ID = "RelayState";
                relayStateHidden.Name = "RelayState";
                relayStateHidden.Value = RelayState;
                p.Controls.Add(relayStateHidden);
            }            

            HtmlInputHidden action = new HtmlInputHidden();
            action.Name = Enum.GetName(typeof (SAMLAction), Action);
            action.ID = Enum.GetName(typeof(SAMLAction), Action);
            action.Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(msg));
            p.Controls.Add(action);

            p.Controls.Add(new LiteralControl("<noscript><div><input type=\"submit\" value=\"Continue\"/></div></noscript>"));
            p.Controls.Add(new LiteralControl("</div></form>"));                                      
            p.Controls.Add(new LiteralControl(Environment.NewLine + "</body>" + Environment.NewLine + "</html>"));

            return p;
        }

        #endregion

    }
}