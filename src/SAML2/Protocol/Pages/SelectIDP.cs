using System;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using SAML2.config;
using Saml2.Properties;

namespace SAML2.protocol.pages
{
    /// <summary>
    /// Page that handles selecting an IdP when more than one is configured
    /// </summary>
    public class SelectSaml20IDP : BasePage
    {
        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load"/> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs"/> object that contains the event data.</param>
        protected override void OnLoad(EventArgs e)
        {
            TitleText = Resources.ChooseIDP;
            HeaderText = Resources.ChooseIDP;
            
            BodyPanel.Controls.Add(new LiteralControl(Resources.ChooseDesc));
            BodyPanel.Controls.Add(new LiteralControl("<br/><br/>"));
            SAML20FederationConfig config = ConfigurationReader.GetConfig<SAML20FederationConfig>();            
            
            config.Endpoints.Refresh();

            foreach (IDPEndPoint endPoint in config.IDPEndPoints)
            {
                if (endPoint.metadata != null)
                {
                    HyperLink link = new HyperLink();

                    // Link text. If a name has been specified in web.config, use it. Otherwise, use id from metadata.
                    link.Text = string.IsNullOrEmpty(endPoint.Name) ? endPoint.metadata.EntityId : endPoint.Name;

                    link.NavigateUrl = endPoint.GetIDPLoginUrl();
                    BodyPanel.Controls.Add(link);
                    BodyPanel.Controls.Add(new LiteralControl("<br/>"));
                } else
                {
                    Label label = new Label();                               
                    label.Text = endPoint.Name;
                    label.Style.Add(HtmlTextWriterStyle.TextDecoration, "line-through");
                    BodyPanel.Controls.Add(label);

                    label = new Label();
                    label.Text = " (Metadata not found)";
                    label.Style.Add(HtmlTextWriterStyle.FontSize, "x-small");
                    BodyPanel.Controls.Add(label);

                    BodyPanel.Controls.Add(new LiteralControl("<br/>"));
                }
            }
        }
    }
}