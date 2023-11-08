﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Asn1;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib;

internal sealed class AndroidKey : AttestationVerifier
{
    public static byte[] AttestationExtensionBytes(X509ExtensionCollection exts)
    {
        foreach (var ext in exts)
        {
            if (ext.Oid?.Value is "1.3.6.1.4.1.11129.2.1.17") // AttestationRecordOid
            {
                return ext.RawData;
            }
        }

        return null;
    }

    public static byte[] GetAttestationChallenge(byte[] attExtBytes)
    {
        // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        // attestationChallenge at index 4

        var keyDescription = AsnElt.Decode(attExtBytes);
        return keyDescription.GetSub(4).GetOctetString();
    }

    public static bool FindAllApplicationsField(byte[] attExtBytes)
    {
        // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        // check both software and tee enforced AuthorizationList objects for presence of "allApplications" tag, number 600

        var keyDescription = AsnElt.Decode(attExtBytes);

        var softwareEnforced = keyDescription.GetSub(6).Sub;
        foreach (AsnElt s in softwareEnforced)
        {
            if (s.TagValue is 600)
                return true;
        }

        var teeEnforced = keyDescription.GetSub(7).Sub;
        foreach (AsnElt s in teeEnforced)
        {
            if (s.TagValue is 600)
                return true;
        }

        return false;
    }

    public static bool IsOriginGenerated(byte[] attExtBytes)
    {
        long softwareEnforcedOriginValue = 0;
        long teeEnforcedOriginValue = 0;
        // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        // origin tag is 702
        var keyDescription = AsnElt.Decode(attExtBytes);

        var softwareEnforced = keyDescription.GetSub(6).Sub;
        foreach (AsnElt s in softwareEnforced)
        {
            switch (s.TagValue)
            {
                case 702:
                    softwareEnforcedOriginValue = s.Sub[0].GetInteger();
                    break;
                default:
                    break;
            }
        }

        var teeEnforced = keyDescription.GetSub(7).Sub;
        foreach (AsnElt s in teeEnforced)
        {
            switch (s.TagValue)
            {
                case 702:
                    teeEnforcedOriginValue = s.Sub[0].GetInteger();
                    break;
                default:
                    break;
            }
        }

        return (softwareEnforcedOriginValue is 0 && teeEnforcedOriginValue is 0);
    }

    public static bool IsPurposeSign(byte[] attExtBytes)
    {
        long softwareEnforcedPurposeValue = 2;
        long teeEnforcedPurposeValue = 2;
        // https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        // purpose tag is 1
        var keyDescription = AsnElt.Decode(attExtBytes);
        var softwareEnforced = keyDescription.GetSub(6).Sub;

        foreach (AsnElt s in softwareEnforced)
        {
            switch (s.TagValue)
            {
                case 1:
                    softwareEnforcedPurposeValue = s.Sub[0].Sub[0].GetInteger();
                    break;
                default:
                    break;
            }
        }

        var teeEnforced = keyDescription.GetSub(7).Sub;
        foreach (AsnElt s in teeEnforced)
        {
            switch (s.TagValue)
            {
                case 1:
                    teeEnforcedPurposeValue = s.Sub[0].Sub[0].GetInteger();
                    break;
                default:
                    break;
            }
        }

        return (softwareEnforcedPurposeValue is 2 && teeEnforcedPurposeValue is 2);
    }

    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
        // (handled in base class)
        if (request.AttStmt.Count == 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MissingAndroidKeyAttestationStatement);

        if (!request.TryGetSig(out byte[] sig))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature);

        // 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
        // using the attestation public key in attestnCert with the algorithm specified in alg
        //if (!(request.X5c is CborArray { Length: > 0 } x5cArray))
        if (request.X5c == null || request.X5c.Type != CBORType.Array || request.X5c.Count == 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation);

        var x5cArray = request.X5c.Values;

        if (x5cArray == null || x5cArray.Count == 0 ||
             x5cArray.First().Type != CBORType.ByteString ||
             x5cArray.First().GetByteString().Length == 0)
            throw new Fido2VerificationException("Malformed x5c in android-key attestation");       

        if (!request.TryGetAlg(out var alg))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAndroidKeyAttestationAlgorithm);

        var trustPath = new X509Certificate2[x5cArray.Count];

        for (int i = 0; i < x5cArray.Count; i++)
        {
            if (x5cArray.ElementAt(i).Type == CBORType.ByteString && x5cArray.ElementAt(i).GetByteString().Length > 0)
            {
                var x5cObject = x5cArray.ElementAt(i).GetByteString();
                try
                {
                    trustPath[i] = new X509Certificate2(x5cObject);
                }
                catch (Exception ex) when (i is 0)
                {
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Failed to extract public key from android key: {ex.Message}", ex);
                }
            }
            else
            {
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation);
            }
        }

        X509Certificate2 androidKeyCert = trustPath[0];
        ECDsa androidKeyPubKey = androidKeyCert.GetECDsaPublicKey()!; // attestation public key

        byte[] ecSignature;
        try
        {
            ecSignature = CryptoUtils.SigFromEcDsaSig(sig, androidKeyPubKey.KeySize);
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Failed to decode android key attestation signature from ASN.1 encoded form", ex);
        }

        if (!androidKeyPubKey.VerifyData(request.Data, ecSignature, CryptoUtils.HashAlgFromCOSEAlg(alg)))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature);

        // 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
        if (!request.AuthData.AttestedCredentialData!.CredentialPublicKey.Verify(request.Data, sig))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Incorrect credentialPublicKey in android key attestation");

        // 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash
        var attExtBytes = AttestationExtensionBytes(androidKeyCert.Extensions);
        if (attExtBytes is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Android key attestation certificate contains no AttestationRecord extension");

        try
        {
            var attestationChallenge = GetAttestationChallenge(attExtBytes);
            if (!request.ClientDataHash.SequenceEqual(attestationChallenge))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Mismatch between attestationChallenge and hashedClientDataJson verifying android key attestation certificate extension");
        }
        catch (Exception)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Malformed android key AttestationRecord extension verifying android key attestation certificate extension");
        }

        // 5. Verify the following using the appropriate authorization list from the attestation certificate extension data

        // 5a. The AuthorizationList.allApplications field is not present, since PublicKeyCredential MUST be bound to the RP ID
        if (FindAllApplicationsField(attExtBytes))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Found all applications field in android key attestation certificate extension");

        // 5bi. The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED ( which == 0).
        if (!IsOriginGenerated(attExtBytes))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension");

        // 5bii. The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
        if (!IsPurposeSign(attExtBytes))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension");

        return (AttestationType.Basic, trustPath);
    }
}
