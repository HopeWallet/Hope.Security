namespace SecureSharp.Encryption.AdvancedSymmetric
{
    public interface IAdvancedEntropyEncryptor
    {
        /// <summary>
        /// Encrypts <see langword="string"/> data with only the entropy from the object creation.
        /// </summary>
        /// <param name="data"> The <see langword="string"/> data to encrypt. </param>
        /// <returns> The encrypted <see langword="string"/> data. </returns>
        string Encrypt(string data);

        /// <summary>
        /// Encrypts <see langword="byte"/>[] data with only the entropy from the object creation.
        /// </summary>
        /// <param name="data"> The <see langword="byte"/>[] data to encrypt. </param>
        /// <returns> The encrypted <see langword="byte"/>[] data. </returns>
        byte[] Encrypt(byte[] data);

        /// <summary>
        /// Encrypts <see langword="string"/> data with an additional entropy parameter.
        /// </summary>
        /// <param name="data"> The <see langword="string"/> data to encrypt. </param>
        /// <param name="entropy"> The additional entropy to apply to the encryption. </param>
        /// <returns> The encrypted <see langword="string"/> data. </returns>
        string Encrypt(string data, string entropy);

        /// <summary>
        /// Encrypts <see langword="string"/> data with an additional entropy parameter.
        /// </summary>
        /// <param name="data"> The <see langword="string"/> data to encrypt. </param>
        /// <param name="entropy"> The additional entropy to apply to the encryption. </param>
        /// <returns> The encrypted <see langword="byte"/>[] data. </returns>
        string Encrypt(string data, byte[] entropy);

        /// <summary>
        /// Encrypts <see langword="byte"/>[] data with an additional entropy parameter.
        /// </summary>
        /// <param name="data"> The <see langword="byte"/>[] data to encrypt. </param>
        /// <param name="entropy"> The additional entropy to apply to the encryption. </param>
        /// <returns> The encrypted <see langword="byte"/>[] data. </returns>
        byte[] Encrypt(byte[] data, string entropy);

        /// <summary>
        /// Decrypts <see langword="string"/> data with only the entropy from the object creation.
        /// </summary>
        /// <param name="encryptedData"> The encrypted <see langword="string"/> data to decrypt. </param>
        /// <returns> The decrypted <see langword="string"/> data. </returns>
        string Decrypt(string encryptedData);

        /// <summary>
        /// Decrypts <see langword="byte"/>[] data with only the entropy from the object creation.
        /// </summary>
        /// <param name="encryptedData"> The encrypted <see langword="byte"/>[] data to decrypt. </param>
        /// <returns> The decrypted <see langword="byte"/>[] data. </returns>
        byte[] Decrypt(byte[] encryptedData);

        /// <summary>
        /// Decrypts <see langword="string"/> data using the additional entropy parameter.
        /// </summary>
        /// <param name="encryptedData"> The encrypted <see langword="string"/> data to decrypt. </param>
        /// <param name="entropy"> The additional entropy to use to decrypt the data. </param>
        /// <returns> The decrypted <see langword="string"/> data. </returns>
        string Decrypt(string encryptedData, string entropy);

        /// <summary>
        /// Decrypts <see langword="string"/> data using the additional entropy parameter.
        /// </summary>
        /// <param name="encryptedData"> The encrypted <see langword="string"/> data to decrypt. </param>
        /// <param name="entropy"> The additional entropy to use to decrypt the data. </param>
        /// <returns> The decrypted <see langword="string"/> data. </returns>
        string Decrypt(string encryptedData, byte[] entropy);

        /// <summary>
        /// Decrypts <see langword="byte"/>[] data using the additional entropy parameter.
        /// </summary>
        /// <param name="encryptedData"> The encrypted <see langword="byte"/>[] data to decrypt. </param>
        /// <param name="entropy"> The additional entropy to use to decrypt the data. </param>
        /// <returns> The decrypted <see langword="byte"/>[] data. </returns>
        byte[] Decrypt(byte[] encryptedData, string entropy);

        /// <summary>
        /// Encrypts <see langword="byte"/>[] data with an additional entropy parameter.
        /// </summary>
        /// <param name="data"> The <see langword="byte"/>[] data to encrypt. </param>
        /// <param name="entropy"> The additional entropy to apply to the encryption. </param>
        /// <returns> The encrypted <see langword="byte"/>[] data. </returns>
        byte[] Encrypt(byte[] data, byte[] entropy);

        /// <summary>
        /// Decrypts <see langword="byte"/>[] data using the additional entropy parameter.
        /// </summary>
        /// <param name="encryptedData"> The encrypted <see langword="byte"/>[] data to decrypt. </param>
        /// <param name="entropy"> The additional entropy to use to decrypt the data. </param>
        /// <returns> The decrypted <see langword="byte"/>[] data. </returns>
        byte[] Decrypt(byte[] encryptedData, byte[] entropy);
    }
}