using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class SHA3PasswordHashing : PBKDF2PasswordHashing<Sha3Digest>
    {
    }
}
