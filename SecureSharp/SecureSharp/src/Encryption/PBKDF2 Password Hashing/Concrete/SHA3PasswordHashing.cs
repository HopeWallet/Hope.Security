using Org.BouncyCastle.Crypto.Digests;

namespace SecureSharp.Encryption.PBKDF2
{
    public sealed class SHA3PasswordHashing : PBKDF2PasswordHashing<Sha3Digest>
    {
    }
}
