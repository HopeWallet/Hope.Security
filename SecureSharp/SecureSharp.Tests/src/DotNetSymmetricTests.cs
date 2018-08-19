using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSharp.Encryption.AdvancedSymmetric.DotNetSymmetric;

namespace SecureSharpTests
{
    [TestClass]
    public sealed class DotNetSymmetricTests
    {
        [TestMethod]
        public void DESEncryptorTest()
        {
            string encryptedData = string.Empty;

            using (var aes = new AesEncryptor())
                encryptedData = aes.Encrypt("my data", "my entropy");

            using (var aes = new AesEncryptor())
                Assert.AreEqual("my data", aes.Decrypt(encryptedData, "my entropy"));
        }

        [TestMethod]
        public void RC2EncryptorTest()
        {
            string encryptedData = string.Empty;

            using (var rijndael = new RijndaelEncryptor())
                encryptedData = rijndael.Encrypt("my data", "my entropy");

            using (var rijndael = new RijndaelEncryptor())
                Assert.AreEqual("my data", rijndael.Decrypt(encryptedData, "my entropy"));
        }
    }
}
