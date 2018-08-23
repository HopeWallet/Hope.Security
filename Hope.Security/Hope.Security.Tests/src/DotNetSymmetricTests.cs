using Hope.Security.SymmetricEncryption.DotNetSymmetric;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Hope.SecurityTests
{
    [TestClass]
    public sealed class DotNetSymmetricTests
    {
        [TestMethod]
        public void AesEncryptorTest()
        {
            string encryptedData = string.Empty;

            using (var aes = new AesEncryptor())
                encryptedData = aes.Encrypt("my data", "my entropy");

            using (var aes = new AesEncryptor())
                Assert.AreEqual("my data", aes.Decrypt(encryptedData, "my entropy"));
        }

        [TestMethod]
        public void RijndaelEncryptorTest()
        {
            string encryptedData = string.Empty;

            using (var rijndael = new RijndaelEncryptor())
                encryptedData = rijndael.Encrypt("my data", "my entropy");

            using (var rijndael = new RijndaelEncryptor())
                Assert.AreEqual("my data", rijndael.Decrypt(encryptedData, "my entropy"));
        }
    }
}