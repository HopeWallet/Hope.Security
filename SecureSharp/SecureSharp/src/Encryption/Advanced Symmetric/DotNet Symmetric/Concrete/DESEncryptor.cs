using System.Security.Cryptography;

namespace SecureSharp.Encryption.AdvancedSymmetric.DotNetSymmetric
{
    /// <summary>
    /// SymmetricEncryptor class used for encrypting data using the <see cref="DESCryptoServiceProvider"/> <see cref="SymmetricAlgorithm"/>.
    /// </summary>
    public sealed class DESEncryptor : SymmetricEncryptor<DESEncryptor, DESCryptoServiceProvider>
    {
        /// <summary>
        /// The key size of the <see cref="SymmetricAlgorithm"/>.
        /// </summary>
        protected override int KeySize => 64;

        /// <summary>
        /// The number of bytes to use for the salt and iv for the <see cref="SymmetricAlgorithm"/>.
        /// </summary>
        protected override int SaltIvByteSize => 8;

        /// <summary>
        /// Initializes the <see cref="DESEncryptor"/> by assigning all additional encryptors to encrypt the data with.
        /// </summary>
        /// <param name="encryptors"> The encryptors to encrypt/decrypt data with. </param>
        public DESEncryptor(params object[] encryptors) : base(encryptors)
        {
        }

        /// <summary>
        /// Initializes the <see cref="DESEncryptor"/>.
        /// </summary>
        public DESEncryptor()
        {
        }
    }
}
