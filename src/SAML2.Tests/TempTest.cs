using System;
using NUnit.Framework;

namespace dk.nita.test.Saml20
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