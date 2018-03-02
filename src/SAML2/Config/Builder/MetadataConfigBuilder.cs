using System;
using System.Collections.Generic;

namespace SAML2.Config.Builder
{
    /// <summary>
    /// <see cref="MetadataConfig"/> builder.
    /// </summary>
    public class MetadataConfigBuilder
    {
        /// <summary>
        /// The contacts.
        /// </summary>
        private IList<Contact> _contacts;

        /// <summary>
        /// Whether to exclude the artifact endpoints or not.
        /// </summary>
        private bool _excludeArtifactEndpoints;

        /// <summary>
        /// The lifetime.
        /// </summary>
        private TimeSpan _lifetime;

        /// <summary>
        /// The organization.
        /// </summary>
        private Organization _organization;

        /// <summary>
        /// The requested attributes.
        /// </summary>
        private IList<Attribute> _requestedAttributes;

        /// <summary>
        /// Initializes a new instance of the <see cref="MetadataConfigBuilder"/> class.
        /// </summary>
        public MetadataConfigBuilder()
        {
            _contacts = new List<Contact>();
            _lifetime = new TimeSpan(7, 0, 0, 0);
            _requestedAttributes = new List<Attribute>();
        }

        /// <summary>
        /// Builds a <see cref="MetadataConfig"/> based on the current builder properties.
        /// </summary>
        /// <returns>A <see cref="MetadataConfig"/>.</returns>
        public MetadataConfig Build()
        {
            var config = new MetadataConfig();

            config.ExcludeArtifactEndpoints = _excludeArtifactEndpoints;
            config.Lifetime = _lifetime;
            config.Organization = _organization;

            foreach (var contact in _contacts)
            {
                config.Contacts.Add(contact);
            }

            foreach (var requestedAttribute in _requestedAttributes)
            {
                config.RequestedAttributes.Add(requestedAttribute);
            }

            return config;
        }

        /// <summary>
        /// Adds a <see cref="Contact"/> to the metadata config.
        /// </summary>
        /// <param name="contact"><see cref="Contact"/> to add.</param>
        /// <returns>The <see cref="MetadataConfigBuilder"/>.</returns>
        public MetadataConfigBuilder AddContact(Contact contact)
        {
            _contacts.Add(contact);
            return this;
        }

        /// <summary>
        /// Adds a <see cref="Attribute"/> to the metadata config.
        /// </summary>
        /// <param name="requestedAttribute"><see cref="Attribute"/> to add.</param>
        /// <returns>The <see cref="MetadataConfigBuilder"/>.</returns>
        public MetadataConfigBuilder AddRequestedAttribute(Attribute requestedAttribute)
        {
            _requestedAttributes.Add(requestedAttribute);
            return this;
        }

        /// <summary>
        /// Turns on excluding the artifact endpoints from metadata generation.
        /// </summary>
        /// <param name="value"><c>true</c> or <c>false</c>.</param>
        /// <returns>The <see cref="MetadataConfigBuilder"/>.</returns>
        public MetadataConfigBuilder ExcludeArtifactEndpoints(bool value)
        {
            _excludeArtifactEndpoints = value;
            return this;
        }

        /// <summary>
        /// Configures the lifetime metadata.
        /// </summary>
        /// <param name="lifetime">The lifetime timespan.</param>
        /// <returns>The <see cref="MetadataConfigBuilder"/>.</returns>
        public MetadataConfigBuilder WithLifetime(TimeSpan lifetime)
        {
            _lifetime = lifetime;
            return this;
        }

        /// <summary>
        /// Configures the <see cref="Organization"/> metadata.
        /// </summary>
        /// <param name="organization">The <see cref="Organization"/> information.</param>
        /// <returns>The <see cref="MetadataConfigBuilder"/>.</returns>
        public MetadataConfigBuilder WithOrganization(Organization organization)
        {
            _organization = organization;
            return this;
        }
    }
}
