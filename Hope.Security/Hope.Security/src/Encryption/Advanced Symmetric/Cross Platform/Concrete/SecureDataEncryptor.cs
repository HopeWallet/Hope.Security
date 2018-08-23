using Hope.Random;
using Hope.Security.Encryption.AdvancedSymmetric.DotNetDPAPI;
using Hope.Security.Encryption.AdvancedSymmetric.DotNetSymmetric;

namespace Hope.Security.Encryption.AdvancedSymmetric.CrossPlatform
{
    /// <summary>
    /// Cross platform class which encrypts/decrypts data for use across multiple sessions.
    /// </summary>
    public sealed class SecureDataEncryptor : CrossPlatformEncryptor<WindowsDataEncryptor, AesEncryptor>
    {
        /// <summary>
        /// Whether this <see cref="CrossPlatformEncryptor"/> implements shorter term encryption methods.
        /// </summary>
        protected override bool IsEphemeral => false;

        /// <summary>
        /// Initializes the <see cref="SecureDataEncryptor"/> by assigning the encryptors to the <see cref="CrossPlatformEncryptor"/>.
        /// </summary>
        /// <param name="encryptors"> The additional encryptors to use as our advanced entropy. </param>
        public SecureDataEncryptor(params object[] encryptors) : base(encryptors)
        {
        }

        /// <summary>
        /// Initializes the <see cref="SecureDataEncryptor"/> given the <see cref="AdvancedSecureRandom"/> instance to use for our encryption.
        /// </summary>
        /// <param name="secureRandom"> The <see cref="AdvancedSecureRandom"/> instance to use for our encryption. </param>
        public SecureDataEncryptor(AdvancedSecureRandom secureRandom) : base(secureRandom)
        {
        }
    }
}