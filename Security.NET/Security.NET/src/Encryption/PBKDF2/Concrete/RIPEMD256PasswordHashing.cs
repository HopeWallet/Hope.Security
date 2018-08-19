using Org.BouncyCastle.Crypto.Digests;

namespace SecurityNET.Encryption.PBKDF2
{
    public sealed class RIPEMD256PasswordHashing : PBKDF2PasswordHashing<RipeMD256Digest>
    {
    }
}
