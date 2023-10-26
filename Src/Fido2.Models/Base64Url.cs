﻿using System;
using System.Buffers;
using System.Buffers.Text;

namespace Fido2NetLib;

/// <summary>
/// Helper class to handle Base64Url. Based on Carbon.Jose source code.
/// </summary>
public static class Base64Url // TODO : cleanup not used stuff
{
    /// <summary>
    /// Converts arg data to a Base64Url encoded string.
    /// </summary>
    public static string Encode(ReadOnlySpan<byte> arg)
    {
        int base64Length = (int)(((long)arg.Length + 2) / 3 * 4);

        char[] pooledBuffer = ArrayPool<char>.Shared.Rent(base64Length);

        //Convert.TryToBase64Chars(arg, pooledBuffer, out int encodedLength);
        int encodedLength = Convert.ToBase64CharArray(arg.ToArray(), 0, arg.Length, pooledBuffer, 0);

        Span<char> base64Url = pooledBuffer.AsSpan(0, encodedLength);

        for (int i = 0; i < base64Url.Length; i++)
        {
            ref char c = ref base64Url[i];

            switch (c)
            {
                case '+':
                    c = '-';
                    break;
                case '/':
                    c = '_';
                    break;
            }
        }

        int equalIndex = base64Url.IndexOf('=');

        if (equalIndex > -1) // remove trailing equal characters
        {
            base64Url = base64Url.Slice(0, equalIndex);
        }

        var result = new string(base64Url.ToArray());

        ArrayPool<char>.Shared.Return(pooledBuffer, clearArray: true);

        return result;
    }

    public static string Encode(byte[] arg)
    {
        string s = Convert.ToBase64String(arg); // Standard base64 encoder

        s = s.Split('=')[0]; // Remove any trailing '='s
        s = s.Replace('+', '-'); // 62nd char of encoding
        s = s.Replace('/', '_'); // 63rd char of encoding

        return s;
    }

    /// <summary>
    /// Decodes a Base64Url encoded string to its raw bytes.
    /// </summary>
    public static byte[] Decode(ReadOnlySpan<char> text)
    {
        int padCharCount = (text.Length % 4) switch
        {
            2 => 2,
            3 => 1,
            _ => 0
        };

        int encodedLength = text.Length + padCharCount;

        char[] buffer = ArrayPool<char>.Shared.Rent(encodedLength);

        text.CopyTo(buffer);

        for (int i = 0; i < text.Length; i++)
        {
            ref char c = ref buffer[i];

            switch (c)
            {
                case '-':
                    c = '+';
                    break;
                case '_':
                    c = '/';
                    break;
            }
        }

        if (padCharCount == 1)
        {
            buffer[encodedLength - 1] = '=';
        }
        else if (padCharCount == 2)
        {
            buffer[encodedLength - 1] = '=';
            buffer[encodedLength - 2] = '=';
        }

        var result = Convert.FromBase64CharArray(buffer, 0, encodedLength);

        ArrayPool<char>.Shared.Return(buffer, true);

        return result;
    }


    /// <summary>
    /// Decodes a Base64Url encoded string to its raw bytes.
    /// </summary>
    public static byte[] DecodeUtf8(ReadOnlySpan<byte> text)
    {
        int padCharCount = (text.Length % 4) switch
        {
            2 => 2,
            3 => 1,
            _ => 0
        };

        int encodedLength = text.Length + padCharCount;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(encodedLength);

        text.CopyTo(buffer);

        for (int i = 0; i < text.Length; i++)
        {
            ref byte c = ref buffer[i];

            switch ((char)c)
            {
                case '-':
                    c = (byte)'+';
                    break;
                case '_':
                    c = (byte)'/';
                    break;
            }
        }

        if (padCharCount == 1)
        {
            buffer[encodedLength - 1] = (byte)'=';
        }
        else if (padCharCount == 2)
        {
            buffer[encodedLength - 1] = (byte)'=';
            buffer[encodedLength - 2] = (byte)'=';
        }

        if (OperationStatus.Done != Base64.DecodeFromUtf8InPlace(buffer.AsSpan(0, encodedLength), out int decodedLength))
        {
            throw new FormatException("The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.");
        }

        var result = buffer.AsSpan(0, decodedLength).ToArray();

        ArrayPool<byte>.Shared.Return(buffer, true);

        return result;
    }

    public static byte[] Decode(string arg)
    {
        if (arg is null)
        {
            throw new ArgumentNullException(nameof(arg));
        }

        string s = arg;
        s = s.Replace('-', '+'); // 62nd char of encoding
        s = s.Replace('_', '/'); // 63rd char of encoding

        switch (s.Length % 4) // Pad with trailing '='s
        {
            case 0:
                break; // No pad chars in this case
            case 2:
                s += "==";
                break; // Two pad chars
            case 3:
                s += "=";
                break; // One pad char
            default:
                throw new FormatException("The provided input is not valid base64 encoded string.");
        }

        return Convert.FromBase64String(s); // Standard base64 decoder
    }
}
