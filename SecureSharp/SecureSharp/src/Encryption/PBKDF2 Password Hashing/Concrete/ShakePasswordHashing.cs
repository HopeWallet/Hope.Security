using Org.BouncyCastle.Crypto.Digests;

namespace SecureSharp.Encryption.PBKDF2
{
    public sealed class ShakePasswordHashing : PBKDF2PasswordHashing<ShakeDigest>
    {
    }
}
