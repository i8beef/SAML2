using System;
using NUnit.Framework;

namespace SAML2.Tests.Saml20
{
    [TestFixture]
    public class TempTest
    {        
        [Test, Explicit]
        public void Test_01()
        {
            Assert.IsTrue(Uri.IsWellFormedUriString("saml.safewhere.net.virk.SPArtifact1", UriKind.RelativeOrAbsolute));
        }
    }
}