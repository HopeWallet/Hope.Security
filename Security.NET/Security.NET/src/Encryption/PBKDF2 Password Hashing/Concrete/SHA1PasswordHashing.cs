using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class SHA1PasswordHashing : PBKDF2PasswordHashing<Sha1Digest>
    {
    }
}
