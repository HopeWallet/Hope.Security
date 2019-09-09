using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/// <summary>
/// Class with string data extensions.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Checks if two strings characters are equal, ignoring uppercase or lowercase differences.
    /// </summary>
    /// <param name="str1"> The first <see langword="string"/> to compare. </param>
    /// <param name="str2"> The second <see langword="string"/> to compare. </param>
    /// <param name="trimEmptyChars"> Trims the empty spaces and characters when comparing the <see langword="string"/> values. </param>
    /// <returns> Whether the two <see langword="string"/> values are equal. </returns>
    public static bool EqualsIgnoreCase(this string str1, string str2, bool trimEmptyChars = false)
        => string.Equals(trimEmptyChars ? str1.Trim() : str1, trimEmptyChars ? str2.Trim() : str2, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Trims the end of a string if it is past a certain length, and adds a certain string to the end if it was over the length.
    /// </summary>
    /// <param name="str"> The string to check. </param>
    /// <param name="maxLength"> The maximum length of this string. </param>
    /// <param name="endCharacters"> The characters to add to the end of the string if it is over the maximum length. </param>
    /// <returns> The trimmed string if it was over the maximum length, otherwise the same string. </returns>
    public static string LimitEnd(this string str, int maxLength, string endCharacters = "") => str.Length <= maxLength ? str : str.Substring(0, maxLength) + endCharacters;

    /// <summary>
    /// Converts a hex string to a byte array.
    /// </summary>
    /// <param name="str"> The hexadecimal string to convert. </param>
    /// <returns> The byte data of the string. </returns>
    public static byte[] GetHexBytes(this string str)
    {
        int numberChars = str.Length;
        byte[] bytes = new byte[numberChars / 2];

        for (int i = 0; i < numberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(str.Substring(i, 2), 16);

        return bytes;
    }

    /// <summary>
    /// Converts a Base64 string to a byte array.
    /// </summary>
    /// <param name="str"> The Base64 string to convert. </param>
    /// <returns> The byte data of the string. </returns>
    public static byte[] GetBase64Bytes(this string str) => string.IsNullOrEmpty(str) ? null : Convert.FromBase64String(str);

    /// <summary>
    /// Converts string to a byte array using UTF8 encoding.
    /// </summary>
    /// <param name="str"> The string to encode. </param>
    /// <returns> The string encoded to UTF8 bytes. </returns>
    public static byte[] GetUTF8Bytes(this string str) => string.IsNullOrEmpty(str) ? null : Encoding.UTF8.GetBytes(str);
}
