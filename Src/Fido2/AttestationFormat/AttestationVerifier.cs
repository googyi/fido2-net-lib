using System.Security.Cryptography.X509Certificates;
using Asn1;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib;

public abstract class AttestationVerifier
{
    public (AttestationType, X509Certificate2[]) Verify(CBORObject attStmt, AuthenticatorData authenticatorData, byte[] clientDataHash)
    {
        return Verify(new VerifyAttestationRequest(attStmt, authenticatorData, clientDataHash));
    }

    public abstract (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request);

    public static AttestationVerifier Create(string formatIdentifier)
    {
        #pragma warning disable format
        return formatIdentifier switch
        {
            "none"              => new None(),             // https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
            "tpm"               => new Tpm(),              // https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
            "android-key"       => new AndroidKey(),       // https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
            "android-safetynet" => new AndroidSafetyNet(), // https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation
            "fido-u2f"          => new FidoU2f(),          // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
            "packed"            => new Packed(),           // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
            "apple"             => new Apple(),            // https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
            "apple-appattest"   => new AppleAppAttest(),   // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server  
            _                   => throw new Fido2VerificationException(Fido2ErrorCode.UnknownAttestationType, $"Unknown attestation type. Was '{formatIdentifier}'")
        };
        #pragma warning restore format
    }

    internal static bool IsAttnCertCACert(X509ExtensionCollection exts)
    {
        foreach (var ext in exts)
        {
            if (ext.Oid.Value.Equals("2.5.29.19") && ext is X509BasicConstraintsExtension baseExt)
            {
                return baseExt.CertificateAuthority;
            }
        }
        return true;
    }

    internal static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
    {
        byte[] aaguid = null;
        foreach (var ext in exts)
        {
            if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
            {
                var decodedAaguid = AsnElt.Decode(ext.RawData);
                decodedAaguid.CheckTag(AsnElt.OCTET_STRING);
                decodedAaguid.CheckPrimitive();
                aaguid = decodedAaguid.GetOctetString();

                //The extension MUST NOT be marked as critical
                if (true == ext.Critical)
                    throw new Fido2VerificationException("extension MUST NOT be marked as critical");

                break;
            }
        }
        return aaguid;
    }

    internal static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
    {
        var u2fTransports = 0;
        foreach (var ext in exts)
        {
            if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
            {
                var decodedU2fTransports = AsnElt.Decode(ext.RawData);
                decodedU2fTransports.CheckPrimitive();

                // some certificates seem to have this encoded as an octet string
                // instead of a bit string, attempt to correct
                if (decodedU2fTransports.TagClass == AsnElt.UNIVERSAL && decodedU2fTransports.TagValue == AsnElt.OCTET_STRING)
                {
                    ext.RawData[0] = AsnElt.BIT_STRING;
                    decodedU2fTransports = AsnElt.Decode(ext.RawData);
                }

                decodedU2fTransports.CheckTag(AsnElt.BIT_STRING);
                u2fTransports = decodedU2fTransports.GetBitString()[0];
                break;
            }
        }
        return u2fTransports;
    }
}
