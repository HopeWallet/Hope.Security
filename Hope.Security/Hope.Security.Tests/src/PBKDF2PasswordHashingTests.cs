using Hope.Security.PBKDF2;
using Hope.Security.PBKDF2.Engines.Blake2b;
using Hope.Security.PBKDF2.Engines.SHA1;
using Hope.Security.PBKDF2.Engines.SHA3;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Hope.SecurityTests
{
    [TestClass]
    public sealed class PBKDF2PasswordHashingTests
    {
        [TestMethod]
        public void TestDifferentPBKDF2Engines()
        {
            PBKDF2PasswordHashing blake2 = new PBKDF2PasswordHashing(new Blake2b_256_Engine());
            PBKDF2PasswordHashing sha1 = new PBKDF2PasswordHashing(new SHA1_Engine());

            string passwordHash = blake2.GetSaltedPasswordHash("password123");

            Assert.IsFalse(sha1.VerifyPassword("password123", passwordHash));
        }

        [TestMethod]
        public void TestCustomHashingParams()
        {
            PBKDF2PasswordHashing defaultPBKDF2 = new PBKDF2PasswordHashing();

            string passwordHash = defaultPBKDF2.GetSaltedPasswordHash("my password", 2500, 256, 512);

            Assert.IsTrue(defaultPBKDF2.VerifyPassword("my password", passwordHash, 2500, 256, 512));
        }

        [TestMethod]
        public void TestDefaultEngine()
        {
            PBKDF2PasswordHashing defaultPBKDF2 = new PBKDF2PasswordHashing();

            string passwordHash = defaultPBKDF2.GetSaltedPasswordHash("my password");

            Assert.IsTrue(defaultPBKDF2.VerifyPassword("my password", passwordHash));
        }

        [TestMethod]
        public void TestBlake2CorrectHash()
        {
            PBKDF2PasswordHashing blake2 = new PBKDF2PasswordHashing(new Blake2b_512_Engine());

            string passwordHash = blake2.GetSaltedPasswordHash("this is my awesome password");

            Assert.IsTrue(blake2.VerifyPassword("this is my awesome password", passwordHash));
        }

        [TestMethod]
        public void TestSHA3IncorrectHash()
        {
            PBKDF2PasswordHashing sha3 = new PBKDF2PasswordHashing(new SHA3_256_Engine());

            string passwordHash = sha3.GetSaltedPasswordHash("epic password yo");

            Assert.IsFalse(sha3.VerifyPassword("epic password", passwordHash));
        }
    }
}
