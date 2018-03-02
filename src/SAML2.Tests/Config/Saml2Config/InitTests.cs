using System.Linq;
using NUnit.Framework;
using SAML2.Config.Builder;

namespace SAML2.Tests.Config.Saml2Config
{
    /// <summary>
    /// Init method tests.
    /// </summary>
    [TestFixture]
    public class InitTests
    {
        /// <summary>
        /// Tests that <see cref="Saml2ConfigBuilder"/> can build a complete configuration.
        /// </summary>
        [Test]
        public void InitWithBuilderWorks()
        {
            // Arrange
            var builder = new Saml2ConfigBuilder();
            builder.AddAction(new SAML2.Config.Action { Name = "ActionName", Type = "ActionType" });
            builder.AddAllowedAudienceUri("AllowedUri");
            builder.WithAssertionValidator("AssertionValidator");

            // Act
            var config = builder.Build();

            // Assert
            Assert.IsNotNull(config.Actions.FirstOrDefault(x => x.Name == "ActionName" && x.Type == "ActionType"));
            Assert.That(config.AllowedAudienceUris.Contains("AllowedUri"));
            Assert.That(config.AssertionProfile.AssertionValidator == "AssertionValidator");
        }
    }
}
