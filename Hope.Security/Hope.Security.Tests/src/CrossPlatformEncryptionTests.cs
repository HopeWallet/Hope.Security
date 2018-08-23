using Hope.Security.SymmetricEncryption.CrossPlatform;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace Hope.SecurityTests
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

        [TestMethod]
        public void MemoryTest2()
        {
            var memoryEncryptor = new SecureMemoryEncryptor();

            byte[] data = new byte[] { 5, 18, 39, 99 };

            byte[] encryptedData = memoryEncryptor.Encrypt(data);
            byte[] decryptedData = memoryEncryptor.Decrypt(encryptedData);

            Assert.AreEqual(5, decryptedData[0]);
            Assert.AreEqual(18, decryptedData[1]);
            Assert.AreEqual(39, decryptedData[2]);
            Assert.AreEqual(99, decryptedData[3]);
        }
    }
}
