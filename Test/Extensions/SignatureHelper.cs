using Asn1;
using System.Security.Cryptography;

namespace fido2_net_lib;

internal static class SignatureHelper
{
    public static byte[] EcDsaSigFromSig(ReadOnlySpan<byte> sig, int keySizeInBits)
    {
        return EcDsaSigFromSig(sig.ToArray(), keySizeInBits);
    }

    public static byte[] EcDsaSigFromSig(byte[] sig, int keySizeInBits)
    {
        var coefficientSize = (int)Math.Ceiling((decimal)keySizeInBits / 8);
        var R = sig.Take(coefficientSize);
        var S = sig.TakeLast(coefficientSize);

        var intR = AsnElt.MakeInteger(R.ToArray());
        var intS = AsnElt.MakeInteger(S.ToArray());
        var ecdsasig = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { intR, intS });
        return ecdsasig.Encode();
    }
}
