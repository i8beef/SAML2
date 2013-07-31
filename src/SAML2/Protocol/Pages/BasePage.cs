using System;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;

namespace SAML2.Protocol.pages
{
    /// <summary>
    /// A base class for asp pages
    /// </summary>
    public class BasePage : Page
    {
        #region Constants

        /// <summary>
        /// AppSetting key for resource
        /// </summary>
        public const string AppSettingsKey = "SafewhereResource";
        /// <summary>
        /// Path to resource
        /// </summary>
        public const string DefaultResourcePath = "/SafewhereResource.ashx";

        #endregion

        #region Constructor functions and related

        /// <summary>
        /// Initializes a new instance of the <see cref="BasePage"/> class.
        /// </summary>
        public BasePage()
        {
            InitControls();
            
        }

        private void InitControls()
        {
            _main = new Panel();
            _main.ID = "mainPanel";

            Controls.Add(new LiteralControl("<?xml version=\"1.0\" encoding=\"utf-8\"?>" + Environment.NewLine));
            Controls.Add(new LiteralControl("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">" + Environment.NewLine));
            _head = new HtmlHead();
            _head.Title = _titleText;
            _head.Controls.Add(GetEncodingMeta());
            
            HtmlLink cssLink = new HtmlLink();
            cssLink.ID = "mainCSS";
            cssLink.Attributes.Add("rel", "stylesheet");
            cssLink.Attributes.Add("type", "text/css");
            cssLink.Attributes.Add("href", ClientScript.GetWebResourceUrl(GetType(), "SAML2.Protocol.Resources.DefaultStyle.css"));
            _head.Controls.Add(cssLink);

            Controls.Add(_head);
            Controls.Add(new LiteralControl("<body>"));

            _body = new Panel();
            _body.ID = "bodyPanel";

            _header = new Panel();
            _header.ID = "headerPanel";

            _footer = new Panel();
            _footer.ID = "footerPanel";            

            _main.Controls.Add(_header);
            _main.Controls.Add(_body);
            _main.Controls.Add(_footer);

            Controls.Add(_main);

            Controls.Add(new LiteralControl(Environment.NewLine + "</body>" + Environment.NewLine + "</html>"));
        }

        #endregion

        #region Properties

        private string _titleText;

        /// <summary>
        /// Gets or sets the title text.
        /// </summary>
        /// <value>The title text.</value>
        public string TitleText
        {
            get { return _titleText; }
            set { _titleText = value; }
        }

        private Panel _main;

        /// <summary>
        /// Gets the main panel.
        /// </summary>
        /// <value>The main panel.</value>
        protected Panel MainPanel
        {
            get { return _main; }
        }

        private Panel _body;

        /// <summary>
        /// Gets the body panel.
        /// </summary>
        /// <value>The body panel.</value>
        protected  Panel BodyPanel
        {
            get{ return _body; }
        }

        private Panel _header;

        /// <summary>
        /// Gets the header panel.
        /// </summary>
        /// <value>The header panel.</value>
        protected Panel HeaderPanel
        {
            get{ return _header; }
        }

        /// <summary>
        /// Sets the header text.
        /// </summary>
        /// <value>The header text.</value>
        protected string HeaderText
        {
            set
            {
                _header.Controls.Clear();
                _header.Controls.Add(new LiteralControl(value));
            }
        }

        private Panel _footer;

        /// <summary>
        /// Gets the footer panel.
        /// </summary>
        /// <value>The footer panel.</value>
        protected Panel FooterPanel
        {
            get { return _footer; }
        }

        /// <summary>
        /// Sets the footer text.
        /// </summary>
        /// <value>The footer text.</value>
        protected string FooterText
        {
            set
            {
                _footer.Controls.Clear();
                _footer.Controls.Add(new LiteralControl(value));
            }
        }

        private HtmlHead _head;

        /// <summary>
        /// Gets the html head element.
        /// </summary>
        /// <value>The head.</value>
        protected HtmlHead Head
        {
            get{ return _head; }
        }

        #endregion

        #region Private utility functions

        private HtmlMeta GetEncodingMeta()
        {
            HtmlMeta enc = new HtmlMeta();
            enc.HttpEquiv = "Content-Type";
            enc.Content = "text/html; charset=utf-8";
            return enc;
        }

        #endregion

    }
}