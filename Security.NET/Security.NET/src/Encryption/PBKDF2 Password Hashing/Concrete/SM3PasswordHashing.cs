using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class SM3PasswordHashing : PBKDF2PasswordHashing<SM3Digest>
    {
    }
}
