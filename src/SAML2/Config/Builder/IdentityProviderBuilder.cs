using System;
using System.Collections.Generic;

namespace SAML2.Config.Builder
{
    /// <summary>
    /// <see cref="IdentityProviderBuilder"/> builder.
    /// </summary>
    public class IdentityProviderBuilder
    {
        /// <summary>
        /// Whether to allow unsolicited responses.
        /// </summary>
        private bool _allowUnsolicitedResponses;

        /// <summary>
        /// The attribute query.
        /// </summary>
        private HttpAuth _attributeQuery;

        /// <summary>
        /// The attribute resolution.
        /// </summary>
        private HttpAuth _attributeResolution;

        /// <summary>
        /// The certificate validations.
        /// </summary>
        private IList<string> _certificateValidations;

        /// <summary>
        /// The common domain cookies.
        /// </summary>
        private IDictionary<string, string> _commonDomainCookies;

        /// <summary>
        /// The endpoints.
        /// </summary>
        private IList<IdentityProviderEndpoint> _endpoints;

        /// <summary>
        /// Whether to enable quirks mode.
        /// </summary>
        private bool _enableQuirksMode;

        /// <summary>
        /// Whether for force authentication.
        /// </summary>
        private bool _forceAuth;

        /// <summary>
        /// The id.
        /// </summary>
        private string _id;

        /// <summary>
        /// Whether is identity provider is the default.
        /// </summary>
        private bool _isDefault;

        /// <summary>
        /// Whether is passive.
        /// </summary>
        private bool _isPassive;

        /// <summary>
        /// The name.
        /// </summary>
        private string _name;

        /// <summary>
        /// Omit assertion signature checks.
        /// </summary>
        private bool _omitAssertionSignatureCheck;

        /// <summary>
        /// The persistent pseudonym mapper type.
        /// </summary>
        private string _persistentPseudonymMapper;

        /// <summary>
        /// The response encoding.
        /// </summary>
        private string _responseEncoding;

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityProviderBuilder"/> class.
        /// </summary>
        public IdentityProviderBuilder()
        {
            _certificateValidations = new List<string>();
            _commonDomainCookies = new Dictionary<string, string>();
            _endpoints = new List<IdentityProviderEndpoint>();
        }

        /// <summary>
        /// Builds a <see cref="IdentityProvider"/> based on the current builder properties.
        /// </summary>
        /// <returns>A <see cref="IdentityProvider"/>.</returns>
        public IdentityProvider Build()
        {
            var config = new IdentityProvider();

            config.AllowUnsolicitedResponses = _allowUnsolicitedResponses;
            config.Default = _isDefault;
            config.ForceAuth = _forceAuth;
            config.Id = _id;
            config.IsPassive = _isPassive;
            config.Name = _name;
            config.OmitAssertionSignatureCheck = _omitAssertionSignatureCheck;
            config.QuirksMode = _enableQuirksMode;
            config.ResponseEncoding = _responseEncoding;

            if (_attributeQuery != null)
            {
                config.AttributeQuery = _attributeQuery;
            }

            if (_attributeResolution != null)
            {
                config.ArtifactResolution = _attributeResolution;
            }

            if (!string.IsNullOrEmpty(_persistentPseudonymMapper))
            {
                config.PersistentPseudonym = new PersistentPseudonym { Mapper = _persistentPseudonymMapper };
            }

            foreach (var certificateValidation in _certificateValidations)
            {
                config.CertificateValidations.Add(certificateValidation);
            }

            foreach (var key in _commonDomainCookies.Keys)
            {
                config.CommonDomainCookie.Add(key, _commonDomainCookies[key]);
            }

            foreach (var endpoint in _endpoints)
            {
                config.Endpoints.Add(endpoint);
            }

            return config;
        }

        /// <summary>
        /// Adds a certificate validation to the config.
        /// </summary>
        /// <param name="certificateValidation">The certificate validation to add.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public IdentityProviderBuilder AddCertificateValidation(string certificateValidation)
        {
            _certificateValidations.Add(certificateValidation);
            return this;
        }

        /// <summary>
        /// Adds a common domain cookie to the config.
        /// </summary>
        /// <param name="key">The common domain cookie key add.</param>
        /// <param name="value">The common domain cookie value add.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public IdentityProviderBuilder AddCommongDomainCookie(string key, string value)
        {
            _commonDomainCookies.Add(key, value);
            return this;
        }

        /// <summary>
        /// Adds an <see cref="IdentityProviderEndpoint"/> to the config.
        /// </summary>
        /// <param name="endpoint">The <see cref="IdentityProviderEndpoint"/> to add.</param>
        /// <returns>The <see cref="ServiceProviderConfigBuilder"/>.</returns>
        public IdentityProviderBuilder AddEndpoint(IdentityProviderEndpoint endpoint)
        {
            _endpoints.Add(endpoint);
            return this;
        }

        /// <summary>
        /// Turns on allowing unsolicited responses.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder AllowUnsolicitedResponses(bool value)
        {
            _allowUnsolicitedResponses = value;
            return this;
        }

        /// <summary>
        /// Enables quirks mode for this identity provider.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder EnableQuirksMode(bool value = true)
        {
            _enableQuirksMode = value;
            return this;
        }

        /// <summary>
        /// Marks this identity provider as force authentication.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder ForceAuth(bool value = true)
        {
            _forceAuth = value;
            return this;
        }

        /// <summary>
        /// Marks this identity provider as the default.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder IsDefault(bool value = true)
        {
            _isDefault = value;
            return this;
        }

        /// <summary>
        /// Marks this identity provider is passive.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder IsPassive(bool value)
        {
            _isPassive = value;
            return this;
        }

        /// <summary>
        /// Enables omitting assertion signature checks..
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder OmitAssertionSignatureCheck(bool value = true)
        {
            _omitAssertionSignatureCheck = value;
            return this;
        }

        /// <summary>
        /// Configures the identity provider attribute query.
        /// </summary>
        /// <param name="predicate">The metadata configuration.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder WithAttributeQuery(Action<HttpAuthBuilder> predicate)
        {
            var builder = new HttpAuthBuilder();
            predicate(builder);
            _attributeQuery = builder.Build();
            return this;
        }

        /// <summary>
        /// Configures the identity provider attribute resolution.
        /// </summary>
        /// <param name="predicate">The metadata configuration.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder WithAttributeResolution(Action<HttpAuthBuilder> predicate)
        {
            var builder = new HttpAuthBuilder();
            predicate(builder);
            _attributeResolution = builder.Build();
            return this;
        }

        /// <summary>
        /// Configures the identity provider id.
        /// </summary>
        /// <param name="id">The identity provider id.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder WithId(string id)
        {
            _id = id;
            return this;
        }

        /// <summary>
        /// Configures the identity provider name.
        /// </summary>
        /// <param name="name">The identity provider name.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder WithName(string name)
        {
            _name = name;
            return this;
        }

        /// <summary>
        /// Configures the identity provider persistent pseudonym mapper.
        /// </summary>
        /// <param name="mapper">The identity provider persistent pseudonym mapper.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder WithPersistentPseudonymMapping(string mapper)
        {
            _persistentPseudonymMapper = mapper;
            return this;
        }

        /// <summary>
        /// Configures the identity provider response encoding.
        /// </summary>
        /// <param name="encoding">The identity provider response encoding.</param>
        /// <returns>The <see cref="IdentityProviderBuilder"/>.</returns>
        public IdentityProviderBuilder WithResponseEncoding(string encoding)
        {
            _responseEncoding = encoding;
            return this;
        }
    }
}
