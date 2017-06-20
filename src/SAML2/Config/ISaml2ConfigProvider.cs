namespace SAML2.Config
{
    public interface ISaml2ConfigProvider
    {
        Saml2Section SAML2Config
        {
            get;
        }
    }
}
