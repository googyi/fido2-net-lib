using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Asn1;
using Fido2NetLib.Internal;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib;

internal sealed class AppleAppAttest : AttestationVerifier
{
    public static byte[] GetAppleAppIdFromCredCertExtValue(X509ExtensionCollection exts)
    {
        var appleExtension = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value is "1.2.840.113635.100.8.5");

        if (appleExtension is null || appleExtension.RawData is null)
            throw new Fido2VerificationException("Extension with OID 1.2.840.113635.100.8.5 not found on Apple AppAttest credCert");

        var appleAttestationASN = AsnElt.Decode(appleExtension.RawData);
        appleAttestationASN.CheckTag(AsnElt.SEQUENCE);
        foreach (AsnElt s in appleAttestationASN.Sub)
        {
            if (s.TagValue is 1204)
            {
                // App ID is the concatenation of your 10-digit team identifier, a period, and your app's CFBundleIdentifier value 
                s.CheckConstructed();
                s.CheckNumSub(1);
                var context = s.GetSub(0);
                context.CheckPrimitive();
                context.CheckTag(AsnElt.OCTET_STRING);

                return context.GetOctetString();
            }
        }
        throw new Fido2VerificationException("Apple AppAttest attestation extension 1.2.840.113635.100.8.5 has invalid data");
    }

    // From https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
    internal static readonly string appleAppAttestationRootCA = "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD";

    public static readonly X509Certificate2 AppleAppAttestRootCA = new(Convert.FromBase64String(appleAppAttestationRootCA));

    // From https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
    // "aaguid field is either appattestdevelop if operating in the development environment..."
    // 61707061-7474-6573-7464-6576656c6f70
    public static readonly Guid devAaguid = new("61707061-7474-6573-7464-6576656c6f70");

    // "...or appattest followed by seven 0x00 bytes if operating in the production environment"
    // 61707061-7474-6573-7400-000000000000
    public static readonly Guid prodAaguid = new("61707061-7474-6573-7400-000000000000");

    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest, starting from the credential certificate in the first data buffer in the array (credcert).
        if (request.X5c == null || request.X5c.Type != CBORType.Array || request.X5c.Count != 2 || request.X5c.Values == null || request.X5c.Values.Count != 2
            || request.X5c.Values.ElementAt(0) == null || request.X5c.Values.ElementAt(1) == null
            || request.X5c.Values.ElementAt(0).Type != CBORType.ByteString || request.X5c.Values.ElementAt(1).Type != CBORType.ByteString
            || request.X5c.Values.ElementAt(0).GetByteString().Length == 0 || request.X5c.Values.ElementAt(1).GetByteString().Length == 0)
        {
            throw new Fido2VerificationException("Malformed x5c in Apple AppAttest attestation");
        }

        var x5cArray = request.X5c.Values.ToArray();

        // Verify the validity of the certificates using Apple's App Attest root certificate.
        X509Certificate2 credCert = new(x5cArray[0].GetByteString());
        X509Certificate2 intermediateCert = new(x5cArray[1].GetByteString());
        VerifyCertification(credCert, intermediateCert, request.AuthData.AttestedCredentialData.AaGuid);

        // 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your app before performing the attestation, and append that hash to the end of the authenticator data (authData from the decoded object).
        // 3. Generate a new SHA256 hash of the composite item to create nonce.
        // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER - encoded ASN.1 sequence.Decode the sequence and extract the single octet string that it contains. Verify that the string equals nonce.
        // Steps 2 - 4 done in the "apple" format verifier
        var apple = new Apple();
        (var attType, var trustPath) = apple.Verify(request);

        // 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
        var credCertPKHash = CryptoUtils.HashData(HashAlgorithmName.SHA256, credCert.GetPublicKey());
        var keyIdentifier = HexConverter.StringToHex(credCert.GetNameInfo(X509NameType.SimpleName, false));

        if (!credCertPKHash.SequenceEqual(keyIdentifier))
        {
            throw new Fido2VerificationException("Public key hash does not match key identifier in Apple AppAttest attestation");
        }

        // 6. Compute the SHA256 hash of your app's App ID, and verify that it’s the same as the authenticator data's RP ID hash.
        var appId = GetAppleAppIdFromCredCertExtValue(credCert.Extensions);
        Span<byte> appIdHash = stackalloc byte[32];
        appIdHash = CryptoUtils.HashData(HashAlgorithmName.SHA256,appId);
        if (!appIdHash.SequenceEqual(request.AuthData.RpIdHash))
        {
            throw new Fido2VerificationException("App ID hash does not match RP ID hash in Apple AppAttest attestation");
        }

        // 7. Verify that the authenticator data's counter field equals 0.
        if (request.AuthData.SignCount != 0)
        {
            throw new Fido2VerificationException("Sign count does not equal 0 in Apple AppAttest attestation");
        }

        // 8. Verify that the authenticator data's aaguid field is either appattestdevelop if operating in the development environment, or appattest followed by seven 0x00 bytes if operating in the production environment.
        if (!request.AuthData.AttestedCredentialData.AaGuid.Equals(devAaguid) && !request.AuthData.AttestedCredentialData.AaGuid.Equals(prodAaguid))
        {
            throw new Fido2VerificationException("Invalid aaguid encountered in Apple AppAttest attestation");
        }

        // 9. Verify that the authenticator data's credentialId field is the same as the key identifier.
        if (!keyIdentifier.SequenceEqual(request.AuthData.AttestedCredentialData.CredentialId))
        {
            throw new Fido2VerificationException("Mismatch between credentialId and keyIdentifier in Apple AppAttest attestation");
        }

        return (attType, trustPath);
    }

    private void VerifyCertification(X509Certificate2 credCert, X509Certificate2 intermediateCert, Guid aaGuid)
    {
        // Verify the validity of the certificates using Apple's App Attest root certificate.
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.ChainPolicy.ExtraStore.Add(AppleAppAttestRootCA);
        // chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; // solved by CryptoUtils.AcceptMathcingUntrustedRoot
        chain.ChainPolicy.ExtraStore.Add(intermediateCert);

        if (aaGuid.Equals(devAaguid))
        {
            // Allow expired leaf cert in development environment
            chain.ChainPolicy.VerificationTime = credCert.NotBefore.AddSeconds(1);
        }

        if (!chain.Build(credCert)) // building chain with trusted root to see different issues like expired cert
        {
            ThrowFido2VerificationException(chain, ignoreStatusFlag: X509ChainStatusFlags.UntrustedRoot);
        }

        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        if (!chain.Build(credCert) && // building chain to check for untrusted root error and accept it explicitly
            !CryptoUtils.AcceptMathcingUntrustedRoot(chain, chain.ChainElements[chain.ChainElements.Count - 1].Certificate)) 
        {
            ThrowFido2VerificationException(chain);
        }

        // if the chain validates, make sure one of the root certificate is one of the chain elements
        // skip the first element, as that is the attestation cert
        if (chain.ChainElements.Cast<X509ChainElement>()
            .Skip(1)
            .Any(x => x.Certificate.Thumbprint.Equals(AppleAppAttestRootCA.Thumbprint, StringComparison.Ordinal)))
            return;

        throw new Fido2VerificationException($"Failed to build chain in Apple AppAttest attestation: root certification is not found in certification chain");
    }

    private void ThrowFido2VerificationException(X509Chain chain, X509ChainStatusFlags ignoreStatusFlag = X509ChainStatusFlags.NoError)
    {
        throw new Fido2VerificationException($"Failed to build chain in Apple AppAttest attestation: {chain.ChainStatus.Where(_ => _.Status != ignoreStatusFlag).FirstOrDefault().StatusInformation}");
    }
}
