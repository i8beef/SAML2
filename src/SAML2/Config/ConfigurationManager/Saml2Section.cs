using System.Configuration;
using SAML2.Config.ConfigurationManager;

namespace SAML2.Config
{
    /// <summary>
    /// SAML2 Configuration Section.
    /// </summary>
    public class Saml2Section : ConfigurationSection
    {
        /// <summary>
        /// Gets the section name.
        /// </summary>
        public static string Name { get { return "saml2"; } }

        #region Elements

        /// <summary>
        /// Gets or sets the actions to perform on successful processing.
        /// </summary>
        /// <value>The actions.</value>
        [ConfigurationProperty("actions")]
        public ActionCollection Actions
        {
            get { return (ActionCollection)base["actions"]; }
            set { base["actions"] = value; }
        }

        /// <summary>
        /// Gets or sets the allowed audience uris.
        /// </summary>
        /// <value>The allowed audience uris.</value>
        [ConfigurationProperty("allowedAudienceUris")]
        public AllowedAudienceUriCollection AllowedAudienceUris
        {
            get { return (AllowedAudienceUriCollection)base["allowedAudienceUris"]; }
            set { base["allowedAudienceUris"] = value; }
        }

        /// <summary>
        /// Gets or sets the assertion profile.
        /// </summary>
        /// <value>The assertion profile configuration.</value>
        [ConfigurationProperty("assertionProfile")]
        public AssertionProfileElement AssertionProfile
        {
            get { return (AssertionProfileElement)base["assertionProfile"]; }
            set { base["assertionProfile"] = value; }
        }

        /// <summary>
        /// Gets or sets the common domain cookie configuration.
        /// </summary>
        /// <value>The common domain cookie configuration.</value>
        [ConfigurationProperty("commonDomainCookie")]
        public CommonDomainCookieElement CommonDomainCookie
        {
            get { return (CommonDomainCookieElement)base["commonDomainCookie"]; }
            set { base["commonDomainCookie"] = value; }
        }

        /// <summary>
        /// Gets or sets the identity providers.
        /// </summary>
        /// <value>The identity providers.</value>
        [ConfigurationProperty("identityProviders")]
        public ConfigurationManager.IdentityProviderCollection IdentityProviders
        {
            get { return (ConfigurationManager.IdentityProviderCollection)base["identityProviders"]; }
            set { base["identityProviders"] = value; }
        }

        /// <summary>
        /// Gets or sets the logging configuration.
        /// </summary>
        /// <value>The logging configuration.</value>
        [ConfigurationProperty("logging")]
        public LoggingElement Logging
        {
            get { return (LoggingElement)base["logging"]; }
            set { base["logging"] = value; }
        }

        /// <summary>
        /// Gets or sets the metadata.
        /// </summary>
        /// <value>The metadata.</value>
        [ConfigurationProperty("metadata")]
        public MetadataElement Metadata
        {
            get { return (MetadataElement)base["metadata"]; }
            set { base["metadata"] = value; }
        }

        /// <summary>
        /// Gets or sets the service provider.
        /// </summary>
        /// <value>The service provider.</value>
        [ConfigurationProperty("serviceProvider")]
        public ServiceProviderElement ServiceProvider
        {
            get { return (ServiceProviderElement)base["serviceProvider"]; }
            set { base["serviceProvider"] = value; }
        }

        /// <summary>
        /// Gets or sets the state service configuration.
        /// </summary>
        /// <value>The state service configuration.</value>
        [ConfigurationProperty("state")]
        public StateElement State
        {
            get { return (StateElement)base["state"]; }
            set { base["state"] = value; }
        }

        #endregion

        /// <summary>
        /// Get configuration from config file.
        /// </summary>
        /// <returns>A configured <see cref="Saml2Config"/> instance.</returns>
        public static Saml2Config GetConfig()
        {
            var section = GetConfigElement();

            var config = new Saml2Config();

            // Actions
            if (section.Actions.ElementInformation.IsPresent)
            {
                foreach (var action in section.Actions)
                {
                    config.Actions.Add(new Action { Name = action.Name, Type = action.Type });
                }
            }

            // Allowed Audience URIs
            if (section.AllowedAudienceUris.ElementInformation.IsPresent)
            {
                foreach (var allowedAudienceUri in section.AllowedAudienceUris)
                {
                    config.AllowedAudienceUris.Add(allowedAudienceUri.Uri);
                }
            }

            // Assertion profile
            if (section.AssertionProfile.ElementInformation.IsPresent)
            {
                config.AssertionProfile.AssertionValidator = section.AssertionProfile.AssertionValidator;
            }

            // Common domain cookie
            if (section.CommonDomainCookie.ElementInformation.IsPresent)
            {
                config.CommonDomainCookie.Enabled = section.CommonDomainCookie.Enabled;
                config.CommonDomainCookie.LocalReaderEndpoint = section.CommonDomainCookie.LocalReaderEndpoint;
            }

            // Identity Providers
            if (section.IdentityProviders.ElementInformation.IsPresent)
            {
                config.IdentityProviderSelectionUrl = section.IdentityProviders.SelectionUrl;
                config.IdentityProviders.Encodings = section.IdentityProviders.Encodings;
                config.IdentityProviders.MetadataLocation = section.IdentityProviders.MetadataLocation;

                foreach (var identityProvider in section.IdentityProviders)
                {
                    var idp = new IdentityProvider
                    {
                        AllowUnsolicitedResponses = identityProvider.AllowUnsolicitedResponses,
                        Default = identityProvider.Default,
                        ForceAuth = identityProvider.ForceAuth,
                        Id = identityProvider.Id,
                        IsPassive = identityProvider.IsPassive,
                        Name = identityProvider.Name,
                        OmitAssertionSignatureCheck = identityProvider.OmitAssertionSignatureCheck,
                        QuirksMode = identityProvider.QuirksMode,
                        ResponseEncoding = identityProvider.ResponseEncoding
                    };

                    if (identityProvider.ArtifactResolution.ElementInformation.IsPresent)
                    {
                        var artifactResolution = new HttpAuth();
                        if (identityProvider.ArtifactResolution.ClientCertificate.ElementInformation.IsPresent)
                        {
                            artifactResolution.ClientCertificate = new Certificate
                            {
                                FindValue = identityProvider.ArtifactResolution.ClientCertificate.FindValue,
                                StoreLocation = identityProvider.ArtifactResolution.ClientCertificate.StoreLocation,
                                StoreName = identityProvider.ArtifactResolution.ClientCertificate.StoreName,
                                ValidOnly = identityProvider.ArtifactResolution.ClientCertificate.ValidOnly,
                                X509FindType = identityProvider.ArtifactResolution.ClientCertificate.X509FindType
                            };
                        }

                        if (identityProvider.ArtifactResolution.Credentials.ElementInformation.IsPresent)
                        {
                            artifactResolution.Credentials = new HttpAuthCredentials
                            {
                                Password = identityProvider.ArtifactResolution.Credentials.Password,
                                Username = identityProvider.ArtifactResolution.Credentials.Username
                            };
                        }

                        idp.ArtifactResolution = artifactResolution;
                    }

                    if (identityProvider.AttributeQuery.ElementInformation.IsPresent)
                    {
                        var attributeQuery = new HttpAuth();
                        if (identityProvider.AttributeQuery.ClientCertificate.ElementInformation.IsPresent)
                        {
                            attributeQuery.ClientCertificate = new Certificate
                            {
                                FindValue = identityProvider.AttributeQuery.ClientCertificate.FindValue,
                                StoreLocation = identityProvider.AttributeQuery.ClientCertificate.StoreLocation,
                                StoreName = identityProvider.AttributeQuery.ClientCertificate.StoreName,
                                ValidOnly = identityProvider.AttributeQuery.ClientCertificate.ValidOnly,
                                X509FindType = identityProvider.AttributeQuery.ClientCertificate.X509FindType
                            };
                        }

                        if (identityProvider.AttributeQuery.Credentials.ElementInformation.IsPresent)
                        {
                            attributeQuery.Credentials = new HttpAuthCredentials
                            {
                                Password = identityProvider.AttributeQuery.Credentials.Password,
                                Username = identityProvider.AttributeQuery.Credentials.Username
                            };
                        }

                        idp.AttributeQuery = attributeQuery;
                    }

                    if (identityProvider.PersistentPseudonym.ElementInformation.IsPresent)
                    {
                        idp.PersistentPseudonym = new PersistentPseudonym { Mapper = identityProvider.PersistentPseudonym.Mapper };
                    }

                    foreach (var certificateValidation in identityProvider.CertificateValidations)
                    {
                        idp.CertificateValidations.Add(certificateValidation.Type);
                    }

                    foreach (var key in identityProvider.CommonDomainCookie.AllKeys)
                    {
                        idp.CommonDomainCookie.Add(identityProvider.CommonDomainCookie[key].Key, identityProvider.CommonDomainCookie[key].Value);
                    }

                    foreach (var endpoint in identityProvider.Endpoints)
                    {
                        idp.Endpoints.Add(new IdentityProviderEndpoint
                        {
                            Binding = endpoint.Binding,
                            ForceProtocolBinding = endpoint.ForceProtocolBinding,
                            TokenAccessor = endpoint.TokenAccessor,
                            Type = endpoint.Type,
                            Url = endpoint.Url
                        });
                    }

                    config.IdentityProviders.Add(idp);
                }
            }

            // Logging config
            if (section.Logging.ElementInformation.IsPresent)
            {
                config.Logging.LoggingFactory = section.Logging.LoggingFactory;
            }

            // Metadata config
            if (section.Metadata.ElementInformation.IsPresent)
            {
                config.Metadata.ExcludeArtifactEndpoints = section.Metadata.ExcludeArtifactEndpoints;
                config.Metadata.Lifetime = section.Metadata.Lifetime;

                if (section.Metadata.Organization.ElementInformation.IsPresent)
                {
                    config.Metadata.Organization = new Organization
                    {
                        Name = section.Metadata.Organization.Name,
                        DisplayName = section.Metadata.Organization.DisplayName,
                        Url = section.Metadata.Organization.Url
                    };
                }

                foreach (var contact in section.Metadata.Contacts)
                {
                    config.Metadata.Contacts.Add(new Contact
                    {
                        Company = contact.Company,
                        Email = contact.Email,
                        GivenName = contact.GivenName,
                        Phone = contact.Phone,
                        SurName = contact.SurName,
                        Type = contact.Type
                    });
                }

                foreach (var attribute in section.Metadata.RequestedAttributes)
                {
                    config.Metadata.RequestedAttributes.Add(new Attribute { IsRequired = attribute.IsRequired, Name = attribute.Name });
                }
            }

            // Service provider
            if (section.ServiceProvider.ElementInformation.IsPresent)
            {
                config.ServiceProvider.AuthenticationContextComparison = section.ServiceProvider.AuthenticationContexts.Comparison;
                config.ServiceProvider.Id = section.ServiceProvider.Id;
                config.ServiceProvider.NameIdFormatAllowCreate = section.ServiceProvider.NameIdFormats.AllowCreate;
                config.ServiceProvider.Server = section.ServiceProvider.Server;

                if (section.ServiceProvider.SigningCertificate.ElementInformation.IsPresent)
                {
                    config.ServiceProvider.SigningCertificate = new Certificate
                    {
                        FindValue = section.ServiceProvider.SigningCertificate.FindValue,
                        StoreLocation = section.ServiceProvider.SigningCertificate.StoreLocation,
                        StoreName = section.ServiceProvider.SigningCertificate.StoreName,
                        ValidOnly = section.ServiceProvider.SigningCertificate.ValidOnly,
                        X509FindType = section.ServiceProvider.SigningCertificate.X509FindType
                    };
                }

                foreach (var authContext in section.ServiceProvider.AuthenticationContexts)
                {
                    config.ServiceProvider.AuthenticationContexts.Add(new AuthenticationContext { Context = authContext.Context, ReferenceType = authContext.ReferenceType });
                }

                foreach (var endpoint in section.ServiceProvider.Endpoints)
                {
                    config.ServiceProvider.Endpoints.Add(new ServiceProviderEndpoint
                    {
                        Binding = endpoint.Binding,
                        Index = endpoint.Index,
                        LocalPath = endpoint.LocalPath,
                        RedirectUrl = endpoint.RedirectUrl,
                        Type = endpoint.Type
                    });
                }

                foreach (var nameIdFormat in section.ServiceProvider.NameIdFormats)
                {
                    config.ServiceProvider.NameIdFormats.Add(nameIdFormat.Format);
                }
            }

            // State config
            if (section.State.ElementInformation.IsPresent)
            {
                config.State.StateServiceFactory = section.State.StateServiceFactory;
                foreach (var setting in section.State.Settings)
                {
                    config.State.Settings.Add(setting.Name, setting.Value);
                }
            }

            return config;
        }

        /// <summary>
        /// Gets a value indicating whether the <see cref="T:System.Configuration.ConfigurationElement"/> object is read-only.
        /// </summary>
        /// <returns>true if the <see cref="T:System.Configuration.ConfigurationElement"/> object is read-only; otherwise, false.</returns>
        public override bool IsReadOnly()
        {
            return false;
        }

        /// <summary>
        /// Gets the base config element without additional metadata parsing, etc.
        /// </summary>
        /// <param name="refresh">Force refresh of config cache.</param>
        /// <returns>A <see cref="Saml2Section"/>.</returns>
        private static Saml2Section GetConfigElement(bool refresh = false)
        {
            if (refresh)
            {
                System.Configuration.ConfigurationManager.RefreshSection(Saml2Section.Name);
            }

            var config = System.Configuration.ConfigurationManager.GetSection(Saml2Section.Name) as Saml2Section;
            if (config == null)
            {
                throw new ConfigurationErrorsException(string.Format("Configuration section \"{0}\" not found", typeof(Saml2Section).Name));
            }

            return config;
        }
    }
}
