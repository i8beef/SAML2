using System;
using SAML2.Utils;
using NUnit.Framework;

namespace SAML2.Tests.Saml20
{
    [TestFixture]
    public class ArtifactTest
    {
        [Test]
        public void ArtifactCreateParse()
        {
            string sourceIdUrl = "https://kleopatra.safewhere.local/Saml2ExtWeb/artifact.ashx";

            byte[] sourceIdHash = ArtifactUtil.GenerateSourceIdHash(sourceIdUrl);

            Assert.That(sourceIdHash.Length == 20, "Unexpected hash length");

            byte[] messageHandle = ArtifactUtil.GenerateMessageHandle();

            Assert.That(messageHandle.Length == 20, "Unexpected hash length");

            Int16 typeCode = 4;

            Int16 endpointIndex = 1;

            string artifact = ArtifactUtil.CreateArtifact(typeCode, endpointIndex, sourceIdHash, messageHandle);

            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[20];
            byte[] parsedMessageHandle = new byte[20];

            Assert.That(
                ArtifactUtil.TryParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex,
                                              ref parsedSourceIdHash, ref parsedMessageHandle), "Unable to parse artifact");

            Assert.That(typeCode == parsedTypeCode, "Original and parsed typeCode did not match");
            Assert.That(endpointIndex == parsedEndpointIndex, "Original and parsed endpointIndex did not match");

            for(int i = 0; i < 20; i++)
            {
                if(sourceIdHash[i] != parsedSourceIdHash[i])
                    Assert.Fail("Original and parsed sourceIdHash are not identical");
            }

            for (int i = 0; i < 20; i++)
            {
                if (messageHandle[i] != parsedMessageHandle[i])
                    Assert.Fail("Original and parsed messageHandle are not identical");
            }
        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateError1()
        {
            Int16 typeCode = 4;
            Int16 endpointIndex = 1;
            byte[] sourceIdHash = new byte[19];
            byte[] messageHandle = new byte[20];

            ArtifactUtil.CreateArtifact(typeCode, endpointIndex, sourceIdHash, messageHandle);
        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateError2()
        {
            Int16 typeCode = 4;
            Int16 endpointIndex = 1;
            byte[] sourceIdHash = new byte[20];
            byte[] messageHandle = new byte[19];

            ArtifactUtil.CreateArtifact(typeCode, endpointIndex, sourceIdHash, messageHandle);
        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void ParseError1()
        {
            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[19];
            byte[] parsedMessageHandle = new byte[20];
            string artifact = string.Empty;

            ArtifactUtil.ParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex, ref parsedSourceIdHash, ref parsedMessageHandle);

        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void ParseError2()
        {
            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[20];
            byte[] parsedMessageHandle = new byte[19];
            string artifact = string.Empty;
            ArtifactUtil.ParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex, ref parsedSourceIdHash, ref parsedMessageHandle);
        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void ParseError3()
        {
            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[20];
            byte[] parsedMessageHandle = new byte[20];
            string artifact = string.Empty;
            ArtifactUtil.ParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex, ref parsedSourceIdHash, ref parsedMessageHandle);

        }

        [Test]
        public void TryParseError1()
        {
            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[19];
            byte[] parsedMessageHandle = new byte[20];
            string artifact = string.Empty;

            bool result = ArtifactUtil.TryParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex, ref parsedSourceIdHash, ref parsedMessageHandle);

            Assert.That(!result, "TryParseArtifact did not fail as expected");
        }

        [Test]
        public void TryParseError2()
        {
            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[20];
            byte[] parsedMessageHandle = new byte[19];
            string artifact = string.Empty;

            bool result = ArtifactUtil.TryParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex, ref parsedSourceIdHash, ref parsedMessageHandle);

            Assert.That(!result, "TryParseArtifact did not fail as expected");
        }

        [Test]
        public void TryParseError3()
        {
            Int16 parsedTypeCode = -1;
            Int16 parsedEndpointIndex = -1;
            byte[] parsedSourceIdHash = new byte[20];
            byte[] parsedMessageHandle = new byte[20];
            string artifact = string.Empty;

            bool result = ArtifactUtil.TryParseArtifact(artifact, ref parsedTypeCode, ref parsedEndpointIndex, ref parsedSourceIdHash, ref parsedMessageHandle);

            Assert.That(!result, "TryParseArtifact did not fail as expected");
        }

    }
}