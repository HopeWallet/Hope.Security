using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSharp.Encryption.AdvancedSymmetric.DotNetSymmetric;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureSharpTests
{
    [TestClass]
    public sealed class DotNetSymmetricTests
    {
        [TestMethod]
        public void DESEncryptorTest()
        {
            string encryptedData = string.Empty;

            using (var des = new DESEncryptor())
                encryptedData = des.Encrypt("my data", "my entropy");

            using (var des = new DESEncryptor())
                Assert.AreEqual("my data", des.Decrypt(encryptedData, "my entropy"));
        }

        [TestMethod]
        public void RC2EncryptorTest()
        {
            string encryptedData = string.Empty;

            using (var des = new RC2Encryptor())
                encryptedData = des.Encrypt("my data", "my entropy");

            using (var des = new RC2Encryptor())
                Assert.AreEqual("my data", des.Decrypt(encryptedData, "my entropy"));
            //RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider();
            //Assert.AreEqual(8, rc2.IV.Length);
            //Assert.AreEqual(16, rc2.Key.Length);
        }
    }
}
