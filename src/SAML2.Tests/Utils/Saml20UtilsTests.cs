using System;
using NUnit.Framework;
using SAML2.Exceptions;
using SAML2.Utils;

namespace SAML2.Tests.Utils
{
    /// <summary>
    /// <see cref="Saml20Utils"/>  tests.
    /// </summary>
    [TestFixture]
    public class Saml20UtilsTests
    {
        /// <summary>
        /// <c>FromUtcString</c> method tests.
        /// </summary>
        [TestFixture]
        public class FromUtcStringMethod
        {
            /// <summary>
            /// Verify can convert UTC formatted string.
            /// </summary>
            [Test]
            public void CanConvertString()
            {
                // Arrange
                var now = DateTime.UtcNow;
                var localtime = now.ToString("o");

                // Act
                var result = Saml20Utils.FromUtcString(localtime);

                // Assert
                Assert.AreEqual(now, result);
            }

            /// <summary>
            /// Verify <see cref="Saml20FormatException"/> is thrown on failure.
            /// </summary>
            [Test]
            public void ThrowsSaml20FormatExceptionOnFailure()
            {
                // Arrange
                var localtime = DateTime.UtcNow.ToString();

                // Act
                Assert.Throws<Saml20FormatException>(() => Saml20Utils.FromUtcString(localtime));
            }
        }

        /// <summary>
        /// <c>ToUtcString</c> method tests.
        /// </summary>
        [TestFixture]
        public class ToUtcStringMethod
        {
            /// <summary>
            /// Verify can convert UTC formatted string.
            /// </summary>
            [Test]
            public void CanConvertToString()
            {
                // Arrange
                var now = DateTime.UtcNow;
                var localtime = now.ToString("o");

                // Act
                var result = Saml20Utils.ToUtcString(now);

                // Correct for XML UTC dropping trailing 0
                if (result.Length != localtime.Length)
                {
                    var zeroPad = new string('0', localtime.Length - result.Length);
                    result = result.Substring(0, result.Length - 1) + zeroPad + "Z";
                }

                // Assert
                Assert.AreEqual(localtime, result);
            }
        }
    }
}
