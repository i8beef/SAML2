using System.IO;
using NUnit.Framework;
using SAML2.Config;

namespace SAML2.Tests
{
    /// <summary>
    /// <see cref="IdentityProviderCollection"/> tests.
    /// </summary>
    [TestFixture]
    public class IdentityProviderCollectionTests
    {
        /// <summary>
        /// Can load metadata file with multiple IDP descriptors.
        /// </summary>
        [Test]
        public void CanLoadMetadataFileWithMultipleIdpDescriptors()
        {
            var collection = new IdentityProviderCollection
            {
                MetadataLocation = Path.Combine(TestContext.CurrentContext.TestDirectory, "Protocol", "MetadataDocs", "multiple-idps")
            };
            collection.Refresh();

            Assert.That(collection.Count == 2);
        }
    }
}
