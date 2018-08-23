using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Hope.Security.Encryption.PBKDF2
{
    public static partial class PBKDF2
    {
        public sealed class Keccak_512 : PBKDF2PasswordHashing
        {
            protected override IDigest PBKDF2Digest => new KeccakDigest(512);
        }
    }
}
