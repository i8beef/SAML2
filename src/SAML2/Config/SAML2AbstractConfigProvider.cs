namespace SAML2.Config
{
    public abstract class SAML2AbstractConfigProvider
    {
        protected SAML2AbstractConfigProvider()
        {
            Saml2Config.Init(this);
        }

        public abstract Saml2Section SAML2Config
        {
            get;
        }
    }
}
