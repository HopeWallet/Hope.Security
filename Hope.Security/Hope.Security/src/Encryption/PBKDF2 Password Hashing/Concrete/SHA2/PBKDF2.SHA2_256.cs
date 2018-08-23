using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Hope.Security.Encryption.PBKDF2
{
    public static partial class PBKDF2
    {
        public sealed class SHA2_256 : PBKDF2PasswordHashing
        {
            protected override IDigest PBKDF2Digest => new Sha256Digest();
        }
    }
}
