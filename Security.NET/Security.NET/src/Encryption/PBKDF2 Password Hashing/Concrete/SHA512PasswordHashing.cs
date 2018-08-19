using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class SHA512PasswordHashing : PBKDF2PasswordHashing<Sha512Digest>
    {
    }
}
