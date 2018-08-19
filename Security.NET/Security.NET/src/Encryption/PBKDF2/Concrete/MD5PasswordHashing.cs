using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class MD5PasswordHashing : PBKDF2PasswordHashing<MD5Digest>
    {
    }
}
