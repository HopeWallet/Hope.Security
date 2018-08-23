using Hope.Security.Encryption.AdvancedSymmetric.DotNetDPAPI;
using Hope.Security.Encryption.AdvancedSymmetric.DotNetSymmetric;
using System.Diagnostics;

namespace Hope.Security.Encryption.AdvancedSymmetric.CrossPlatform
{
    /// <summary>
    /// Cross platform class for encrypting/decrypting certain data in memory to avoid potential tampering.
    /// <para> Data can only be decrypted by the same instance of MemoryEncryptor. </para>
    /// </summary>
    public sealed class SecureMemoryEncryptor : CrossPlatformEncryptor<WindowsMemoryEncryptor, AesEncryptor>
    {
        /// <summary>
        /// Whether this <see cref="CrossPlatformEncryptor"/> implements shorter term encryption methods.
        /// </summary>
        protected override bool IsEphemeral => true;

        /// <summary>
        /// Initializes the <see cref="SecureMemoryEncryptor"/> by assigning the encryptors to the <see cref="CrossPlatformEncryptor"/> 
        /// with additional parameters which hold our current process info.
        /// </summary>
        /// <param name="encryptors"> The additional encryptors to use as our advanced entropy. </param>
        public SecureMemoryEncryptor(params object[] encryptors) : base(
            Process.GetCurrentProcess().Id,
            Process.GetCurrentProcess().MainModule.ModuleName.GetHashCode(),
            encryptors)
        {
        }
    }
}