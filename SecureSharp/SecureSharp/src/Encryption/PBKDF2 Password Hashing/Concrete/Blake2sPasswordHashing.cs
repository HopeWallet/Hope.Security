using Org.BouncyCastle.Crypto.Digests;

namespace SecureSharp.Encryption.PBKDF2
{
    public sealed class Blake2sPasswordHashing : PBKDF2PasswordHashing<Blake2sDigest>
    {
    }
}
