using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class ShakePasswordHashing : PBKDF2PasswordHashing<ShakeDigest>
    {
    }
}
