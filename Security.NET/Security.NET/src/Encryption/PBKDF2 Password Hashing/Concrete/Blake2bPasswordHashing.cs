using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class Blake2bPasswordHashing : PBKDF2PasswordHashing<Blake2bDigest>
    {
    }
}
