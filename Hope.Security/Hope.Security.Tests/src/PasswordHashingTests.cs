using Microsoft.VisualStudio.TestTools.UnitTesting;
using Hope.Security.Encryption.PBKDF2;

namespace SecureSharpTests
{
    [TestClass]
    public sealed class PasswordHashingTests
    {
        [TestMethod]
        public void TestBlake2CorrectHash()
        {
            PBKDF2.Blake2_512 blake2 = new PBKDF2.Blake2_512();

            string passwordHash = blake2.GetSaltedPasswordHash("this is my awesome password");

            Assert.IsTrue(blake2.VerifyPassword("this is my awesome password", passwordHash));
        }

        [TestMethod]
        public void TestSHA3IncorrectHash()
        {
            PBKDF2.SHA3_256 sha3 = new PBKDF2.SHA3_256();

            string passwordHash = sha3.GetSaltedPasswordHash("epic password yo");

            Assert.IsFalse(sha3.VerifyPassword("epic password", passwordHash));
        }
    }
}
