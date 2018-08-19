using Org.BouncyCastle.Crypto.Digests;

namespace SecureSharp.Encryption.PBKDF2
{
    public sealed class SHA512PasswordHashing : PBKDF2PasswordHashing<Sha512Digest>
    {
    }
}
