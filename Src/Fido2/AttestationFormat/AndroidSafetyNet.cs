using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Fido2NetLib.Internal;

using Microsoft.IdentityModel.Tokens;
using PeterO.Cbor;
using Newtonsoft.Json.Linq;

namespace Fido2NetLib;

internal sealed class AndroidSafetyNet : AttestationVerifier
{
    private const int _driftTolerance = 0;

    private X509Certificate2 GetX509Certificate(string certString)
    {
        try
        {
            var certBytes = Convert.FromBase64String(certString);
            return new X509Certificate2(certBytes);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("Could not parse X509 certificate", ex);
        }
    }

    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform 
        // CBOR decoding on it to extract the contained fields
        // (handled in base class)

        // 2. Verify that response is a valid SafetyNet response of version ver
        if (!request.TryGetVer(out string ver))
        {
            throw new Fido2VerificationException(Fido2ErrorMessages.InvalidSafetyNetVersion);
        }

        if (request.AttStmt["response"].Type != CBORType.ByteString || request.AttStmt["response"].GetByteString().Length == 0)
            throw new Fido2VerificationException(Fido2ErrorMessages.InvalidSafetyNetResponse);

        var responseByteString = request.AttStmt["response"].GetByteString();

        var responseJwt = Encoding.UTF8.GetString(responseByteString);

        var jwtComponents = responseJwt.Split('.');

        if (jwtComponents.Length != 3)
            throw new Fido2VerificationException(Fido2ErrorMessages.MalformedSafetyNetJwt);

        var jwtHeaderString = jwtComponents.First();
        JObject jwtHeaderJSON;

        try
        {
            jwtHeaderJSON = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(jwtHeaderString)));
        }
        catch (FormatException)
        {
            throw new Fido2VerificationException(Fido2ErrorMessages.MalformedSafetyNetJwt);
        }

        var x5cEl = jwtHeaderJSON["x5c"] as JArray;

        if (x5cEl == null)
            throw new Fido2VerificationException("SafetyNet response JWT header missing x5c");

        var x5cRawKeys = x5cEl.Values<string>().ToList();

        if (x5cRawKeys.Count == 0)
            throw new Fido2VerificationException("No keys were present in the TOC header in SafetyNet response JWT");

        var certs = new List<X509Certificate2>();
        var keys = new List<SecurityKey>();

        foreach (var certString in x5cRawKeys)
        {
            var cert = GetX509Certificate(certString);
            certs.Add(cert);

            if (cert.GetECDsaPublicKey() is ECDsa ecdsaPublicKey)
            {
                keys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
            }
            else if (cert.GetRSAPublicKey() is RSA rsaPublicKey)
            {
                keys.Add(new RsaSecurityKey(rsaPublicKey));
            }
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken validatedToken;
        try
        {
            tokenHandler.ValidateToken(responseJwt, validationParameters, out validatedToken);
        }
        catch (SecurityTokenException ex)
        {
            throw new Fido2VerificationException("SafetyNet response security token validation failed", ex);
        }

        string nonce = null;
        bool? ctsProfileMatch = null;
        DateTimeOffset? timestamp = null;

        var jwtToken = (JwtSecurityToken)validatedToken;

        foreach (var claim in jwtToken.Claims)
        {
            if (claim is { Type: "nonce", ValueType: "http://www.w3.org/2001/XMLSchema#string" } && claim.Value.Length != 0)
            {
                nonce = claim.Value;
            }
            if (claim is { Type: "ctsProfileMatch", ValueType: "http://www.w3.org/2001/XMLSchema#boolean" })
            {
                ctsProfileMatch = bool.Parse(claim.Value);
            }
            if (claim is { Type: "timestampMs", ValueType: "http://www.w3.org/2001/XMLSchema#integer64" })
            {
                timestamp = DateTimeHelper.UnixEpoch.AddMilliseconds(double.Parse(claim.Value, CultureInfo.InvariantCulture));
            }
        }

        if (!timestamp.HasValue)
        {
            throw new Fido2VerificationException($"SafetyNet timestampMs not found SafetyNet attestation");
        }

        var notAfter = DateTimeOffset.UtcNow.AddMilliseconds(_driftTolerance);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-1).AddMilliseconds(-(_driftTolerance));
        if ((notAfter < timestamp) || ((notBefore) > timestamp.Value))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"SafetyNet timestampMs must be between one minute ago and now, got: {timestamp:o}");
        }

        // 3. Verify that the nonce in the response is identical to the SHA-256 hash of the concatenation of authenticatorData and clientDataHash
        if (string.IsNullOrEmpty(nonce))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Nonce value not found in SafetyNet attestation");

        byte[] nonceHash;
        try
        {
            nonceHash = Convert.FromBase64String(nonce);
        }
        catch (Exception ex)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Nonce value not base64string in SafetyNet attestation", ex);
        }

        Span<byte> dataHash = stackalloc byte[32];
        dataHash = CryptoUtils.HashData(HashAlgorithmName.SHA256, request.Data);

        if (!dataHash.SequenceEqual(nonceHash))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"SafetyNet response nonce / hash value mismatch, nonce {HexConverter.HexToString(nonceHash)}, hash {HexConverter.HexToString(dataHash.ToArray())}");
        }

        // 4. Let attestationCert be the attestation certificate
        var attestationCert = certs[0];
        var subject = attestationCert.GetNameInfo(X509NameType.DnsName, false);

        // 5. Verify that the attestation certificate is issued to the hostname "attest.android.com"
        if (subject is not "attest.android.com")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Invalid SafetyNet attestation cert DnsName. Expected 'attest.android.com'. Was '{subject}'");

        // 6. Verify that the ctsProfileMatch attribute in the payload of response is true
        if (ctsProfileMatch is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SafetyNet response ctsProfileMatch missing");

        if (true != ctsProfileMatch)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "SafetyNet response ctsProfileMatch false");

        return (AttestationType.Basic, new X509Certificate2[] { attestationCert });
    }
}
