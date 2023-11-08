using System;
using System.Text;

namespace Fido2NetLib.Internal;

/// <summary>
/// Converts hexadecimal numbers (byte array) to hex encoded string and vice versa.
/// </summary>
public static class HexConverter
{
    /// <summary>
    /// Converts hexadecimal numbers (byte array) to hex encoded string.
    /// </summary>
    /// <param name="bytearray"></param>
    /// <returns></returns>
    public static string HexToString(byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        StringBuilder sb = new StringBuilder(bytes.Length * 2);

        for (int i = 0; i < bytes.Length; i++)
        {
            int value = bytes[i];
            sb.Append(GetHexDigit(value >> 4));
            sb.Append(GetHexDigit(value & 0xf));
        }

        return sb.ToString();
    }

    private static char GetHexDigit(int value)
    {
        if (value < 10)
            return (char)(value + '0');
        else
            return (char)(value - 10 + 'A');
    }

    /// <summary>
    /// Converts a hex encoded string to hexadecimal numbers (byte array)
    /// </summary>
    /// <param name="text"></param>
    /// <returns></returns>
    public static byte[] StringToHex(string s)
    {
        if (s == null)
            throw new ArgumentNullException(nameof(s));

        byte[] bytes = new byte[s.Length / 2];

        int byteIndex = 0;
        for (int i = 0; i < s.Length; i += 2)
        {
            int digit1 = ParseHexDigit(s[i]);
            int digit2 = ParseHexDigit(s[i + 1]);

            if (digit1 == -1 || digit2 == -1)
                throw new FormatException("Invalid hex string.");

            bytes[byteIndex++] = unchecked((byte)(digit1 << 4 | digit2));
        }

        return bytes;
    }

    public static bool IsInputHexEncoded(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length % 2 != 0)
            return false;

        for (int i = 0; i < s.Length; i++)
        {
            if (ParseHexDigit(s[i]) == -1)
                return false;
        }

        return true;
    }

    private static int ParseHexDigit(char ch)
    {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        else if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        else
            return -1;
    }
}
