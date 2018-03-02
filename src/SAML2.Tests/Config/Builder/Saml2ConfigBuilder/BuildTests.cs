using System.Linq;
using NUnit.Framework;

namespace SAML2.Tests.Config.Builder.Saml2ConfigBuilder
{
    /// <summary>
    /// Build method tests.
    /// </summary>
    [TestFixture]
    public class BuildTests
    {
        /// <summary>
        /// Tests that <see cref="SSAML2.Config.Builder.aml2ConfigBuilder"/> can build a complete configuration.
        /// </summary>
        [Test]
        public void InitWithBuilderWorks()
        {
            // Arrange
            var builder = new SAML2.Config.Builder.Saml2ConfigBuilder();
            builder.AddAction(new SAML2.Config.Action { Name = "ActionName", Type = "ActionType" });
            builder.AddAllowedAudienceUri("AllowedUri");
            builder.WithAssertionValidator("AssertionValidator");

            // Act TODO: Change this out for a validator call
            var config = builder.Build();
            
            // Assert
            Assert.IsNotNull(config.Actions.FirstOrDefault(x => x.Name == "ActionName" && x.Type == "ActionType"));
            Assert.That(config.AllowedAudienceUris.Contains("AllowedUri"));
            Assert.That(config.AssertionProfile.AssertionValidator == "AssertionValidator");
        }
    }
}
