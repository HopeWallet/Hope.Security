using Org.BouncyCastle.Crypto.Digests;

namespace SecureSharp.Encryption.PBKDF2
{
    public sealed class SHA256PasswordHashing : PBKDF2PasswordHashing<Sha256Digest>
    {
    }
}
