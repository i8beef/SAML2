using System;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;

namespace SAML2.Protocol.Pages
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

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="BasePage"/> class.
        /// </summary>
        public BasePage()
        {
            InitControls();
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the title text.
        /// </summary>
        /// <value>The title text.</value>
        public string TitleText { get; set; }

        /// <summary>
        /// Gets the main panel.
        /// </summary>
        /// <value>The main panel.</value>
        protected Panel MainPanel { get; private set; }

        /// <summary>
        /// Gets the body panel.
        /// </summary>
        /// <value>The body panel.</value>
        protected Panel BodyPanel { get; private set; }

        /// <summary>
        /// Gets the header panel.
        /// </summary>
        /// <value>The header panel.</value>
        protected Panel HeaderPanel { get; private set; }

        /// <summary>
        /// Sets the header text.
        /// </summary>
        /// <value>The header text.</value>
        protected string HeaderText
        {
            set
            {
                HeaderPanel.Controls.Clear();
                HeaderPanel.Controls.Add(new LiteralControl(value));
            }
        }

        /// <summary>
        /// Gets the footer panel.
        /// </summary>
        /// <value>The footer panel.</value>
        protected Panel FooterPanel { get; private set; }

        /// <summary>
        /// Sets the footer text.
        /// </summary>
        /// <value>The footer text.</value>
        protected string FooterText
        {
            set
            {
                FooterPanel.Controls.Clear();
                FooterPanel.Controls.Add(new LiteralControl(value));
            }
        }

        /// <summary>
        /// Gets the html head element.
        /// </summary>
        /// <value>The head.</value>
        protected HtmlHead Head { get; private set; }

        #endregion

        #region Private utility functions

        /// <summary>
        /// Gets the encoding meta tag.
        /// </summary>
        /// <returns>The encoding meta tag.</returns>
        private static HtmlMeta GetEncodingMetaTag()
        {
            var enc = new HtmlMeta { HttpEquiv = "Content-Type", Content = "text/html; charset=utf-8" };
            return enc;
        }

        /// <summary>
        /// Initializes the controls.
        /// </summary>
        private void InitControls()
        {
            MainPanel = new Panel { ID = "mainPanel" };

            Controls.Add(new LiteralControl("<?xml version=\"1.0\" encoding=\"utf-8\"?>" + Environment.NewLine));
            Controls.Add(new LiteralControl("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">" + Environment.NewLine));

            Head = new HtmlHead { Title = TitleText };
            Head.Controls.Add(GetEncodingMetaTag());

            Controls.Add(Head);
            Controls.Add(new LiteralControl("<body>"));

            HeaderPanel = new Panel { ID = "headerPanel" };
            BodyPanel = new Panel { ID = "bodyPanel" };
            FooterPanel = new Panel { ID = "footerPanel" };

            MainPanel.Controls.Add(HeaderPanel);
            MainPanel.Controls.Add(BodyPanel);
            MainPanel.Controls.Add(FooterPanel);

            Controls.Add(MainPanel);

            Controls.Add(new LiteralControl(Environment.NewLine + "</body>" + Environment.NewLine + "</html>"));
        }

        #endregion
    }
}