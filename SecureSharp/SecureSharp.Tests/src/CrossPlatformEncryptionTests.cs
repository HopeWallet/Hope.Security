using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSharp.Encryption.AdvancedSymmetric.CrossPlatform;
using System.Security.Cryptography;

namespace SecureSharpTests
{
    [TestClass]
    public sealed class CrossPlatformEncryptionTests
    {
        [TestMethod]
        public void CrossPlatformDataTest()
        {
            string encryptedText = string.Empty;

            using (var dataEncryptor = new SecureDataEncryptor("entropy", 14235, true))
                encryptedText = dataEncryptor.Encrypt("this is my data");

            using (var dataEncryptor = new SecureDataEncryptor("entropy", 14235, true))
                Assert.AreEqual("this is my data", dataEncryptor.Decrypt(encryptedText));
        }

        [TestMethod]
        public void CrossPlatformMemoryTest()
        {
            var memoryEncryptor = new SecureMemoryEncryptor();
            var memoryEncryptor2 = new SecureMemoryEncryptor();

            var encryptedMemory = memoryEncryptor.Encrypt("this is my data");

            // Decrypted encrypted memory with same SecureMemoryEncryptor and data is decrypted successfully
            Assert.AreEqual("this is my data", memoryEncryptor.Decrypt(encryptedMemory));

            // Decrypt encrypted memory with different SecureMemoryEncryptor and exception gets thrown
            Assert.ThrowsException<CryptographicException>(() => memoryEncryptor2.Decrypt(encryptedMemory));
        }
    }
}
