using System.Collections.Generic;
using System.Linq;
using System.Xml;
using NUnit.Framework;
using SAML2.Schema.Metadata;

namespace SAML2.Tests
{
    [TestFixture]
    public class IdentityProviderCollectionTests
    {
        [Test]
        public void CanLoadMetadataFileWithMultipleIdpDescriptors()
        {
            // Note: This is a test bed for the implementation in IdentityProviderCollection.
            var doc = new XmlDocument { PreserveWhitespace = true };

            doc.Load(TestContext.CurrentContext.TestDirectory + @"\Protocol\MetadataDocs\metadata-multiple-idps.xml");
            var idpMetadata = new List<Saml20MetadataDocument>();
            foreach (var child in doc.ChildNodes.Cast<XmlNode>().Where(child => child.NamespaceURI == Saml20Constants.Metadata))
            {
                if (child.LocalName == EntityDescriptor.ElementName)
                {
                    idpMetadata.Add(new Saml20MetadataDocument(doc));
                }
                
                if (child.LocalName == EntitiesDescriptor.ElementName)
                {                    
                    foreach (var entityDescriptor in child.ChildNodes.Cast<XmlNode>().Where(x => x.NamespaceURI == Saml20Constants.Metadata))
                    {
                        var childDoc = new XmlDocument { PreserveWhitespace = true };
                        childDoc.AppendChild(childDoc.ImportNode(entityDescriptor, true));
                        idpMetadata.Add(new Saml20MetadataDocument(childDoc));
                    }
                }
            }

            Assert.That(idpMetadata.Count == 2);
        }
    }
}
