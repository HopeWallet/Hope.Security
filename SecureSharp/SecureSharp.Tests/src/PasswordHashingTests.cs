using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSharp.Encryption.PBKDF2;

namespace SecureSharpTests
{
    [TestClass]
    public sealed class PasswordHashingTests
    {
        [TestMethod]
        public void TestBlake2CorrectHash()
        {
            Blake2bPasswordHashing blake2 = new Blake2bPasswordHashing();

            string passwordHash = blake2.GetSaltedPasswordHash("this is my awesome password");

            Assert.IsTrue(blake2.VerifyPassword("this is my awesome password", passwordHash));
        }

        [TestMethod]
        public void TestSHA3IncorrectHash()
        {
            SHA3PasswordHashing sha3 = new SHA3PasswordHashing();

            string passwordHash = sha3.GetSaltedPasswordHash("epic password yo");

            Assert.IsFalse(sha3.VerifyPassword("epic password", passwordHash));
        }
    }
}
