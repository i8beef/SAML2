using System;
using System.Configuration;
using System.Web.Configuration;
using System.Web.UI;
using Saml2.Properties;

namespace SAML2.Protocol.pages
{
    /// <summary>
    /// A page for displaying error messages
    /// </summary>
    public class ErrorPage : BasePage
    {
        #region Constructor functions

        /// <summary>
        /// Initializes a new instance of the <see cref="ErrorPage"/> class.
        /// </summary>
        public ErrorPage()
        {
            TitleText = Resources.Error;
            HeaderText = Resources.Error;
        }

        #endregion

        #region Properties

        private string _errorText = string.Empty;

        /// <summary>
        /// Gets or sets the error text.
        /// </summary>
        /// <value>The error text.</value>
        public string ErrorText
        {
            get { return _errorText; }
            set { _errorText = value; }
        }

        private bool _overrideConfig = false;

        /// <summary>
        /// Gets or sets a value indicating whether to override config.
        /// </summary>
        /// <value><c>true</c> if config is overridden; otherwise, <c>false</c>.</value>
        public bool OverrideConfig
        {
            get { return _overrideConfig; }
            set { _overrideConfig = value; }
        }

        #endregion

        #region overridden page functions

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load"/> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs"/> object that contains the event data.</param>
        protected override void OnLoad(EventArgs e)
        {
            string err = Resources.GenericError;
            
            Configuration conf = WebConfigurationManager.OpenWebConfiguration(Context.Request.Path);
            CustomErrorsSection ces = (CustomErrorsSection)conf.GetSection("system.web/customErrors");
            if(ces != null && !_overrideConfig)
            {
                switch (ces.Mode)
                {
                    case CustomErrorsMode.Off:
                        err = _errorText;
                        break;
                    case CustomErrorsMode.On:
                        //Display generic error
                        break;
                    case CustomErrorsMode.RemoteOnly:
                        if (Context.Request.IsLocal)
                            err = _errorText;
                        break;
                }
            }else
            {
                //OverrideConfig: Display detailed error message
                err = _errorText;
            }
            
            BodyPanel.Controls.Add(new LiteralControl(err));
            
        }

        #endregion
    }
}