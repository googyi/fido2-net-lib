using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Asn1;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public static class CryptoUtils
{
    private static RandomNumberGenerator rnd = RandomNumberGenerator.Create();

    public static byte[] GetRandomBytes(int byteArrayLength)
    {
        var bytes = new byte[byteArrayLength];
        rnd.GetBytes(bytes);
        return bytes;
    }

    public static byte[] HashData(HashAlgorithmName hashName, ReadOnlySpan<byte> data)
    {
        return HashData(hashName, data.ToArray());
    }

    public static byte[] HashData(HashAlgorithmName hashName, byte[] data)
    {
        return GetHasher(hashName).ComputeHash(data);
    }

    private static HashAlgorithm GetHasher(HashAlgorithmName hashName)
    {
        switch (hashName.Name)
        {
            case "SHA1":
                return SHA1.Create();
            case "SHA256":
            case "HS256":
            case "RS256":
            case "ES256":
            case "PS256":
                return SHA256.Create();
            case "SHA384":
            case "HS384":
            case "RS384":
            case "ES384":
            case "PS384":
                return SHA384.Create();
            case "SHA512":
            case "HS512":
            case "RS512":
            case "ES512":
            case "PS512":
                return SHA512.Create();
            default:
                throw new ArgumentOutOfRangeException(nameof(hashName));
        }
    }

    public static HashAlgorithmName HashAlgFromCOSEAlg(COSE.Algorithm alg)
    {
        return alg switch
        {
            COSE.Algorithm.RS1 => HashAlgorithmName.SHA1,
            COSE.Algorithm.ES256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.ES384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.ES512 => HashAlgorithmName.SHA512,
            COSE.Algorithm.PS256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.PS384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.PS512 => HashAlgorithmName.SHA512,
            COSE.Algorithm.RS256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.RS384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.RS512 => HashAlgorithmName.SHA512,
            COSE.Algorithm.ES256K => HashAlgorithmName.SHA256,
            (COSE.Algorithm)4 => HashAlgorithmName.SHA1,
            (COSE.Algorithm)11 => HashAlgorithmName.SHA256,
            (COSE.Algorithm)12 => HashAlgorithmName.SHA384,
            (COSE.Algorithm)13 => HashAlgorithmName.SHA512,
            COSE.Algorithm.EdDSA => HashAlgorithmName.SHA512,
            _ => throw new Fido2VerificationException(Fido2ErrorMessages.InvalidCoseAlgorithmValue),
        };
    }

    public static bool ValidateTrustChain(X509Certificate2[] trustPath, X509Certificate2[] attestationRootCertificates, bool conformance = false)
    {
        // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-attestationRootCertificates

        // Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
        // Multiple certificates might be used for different batches of the same model.
        // The array does not represent a certificate chain, but only the trust anchor of that chain.
        // A trust anchor can be a root certificate, an intermediate CA certificate or even the attestation certificate itself.

        // Let's check the simplest case first.  If subject and issuer are the same, and the attestation cert is in the list, that's all the validation we need

        // Conformance testing tool v1.7.15
        // P-3
        // Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation that contains batch certificate, that is simply self referenced in the metadata, and check that server succeeds
        // We have the same singular root cert in trustpath and in attestationRootCertificates with mismatching Subject and issuer 
        // therefore it fails validation if we check for Subject vs Issuer
        if (trustPath.Length == 1 && trustPath[0].Subject.Equals(trustPath[0].Issuer, StringComparison.Ordinal)) // && ... should be commented out
        {
            foreach (X509Certificate2 cert in attestationRootCertificates)
            {
                if (cert.Thumbprint.Equals(trustPath[0].Thumbprint, StringComparison.Ordinal))
                {
                    return true;
                }
            }
             return false; // should be commented out
        }

        // If the attestation cert is not self signed, we will need to build a chain
        var chain = new X509Chain();

        // Put all potential trust anchors into extra store
        chain.ChainPolicy.ExtraStore.AddRange(attestationRootCertificates);

        // We don't know the root here, so allow unknown root, and turn off revocation checking
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        // trustPath[0] is the attestation cert, if there are more in the array than just that, add those to the extra store as well, but skip attestation cert
        if (trustPath.Length > 1)
        {
            foreach (X509Certificate2 cert in trustPath.Skip(1)) // skip attestation cert
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }

        // try to build a chain with what we've got
        if (chain.Build(trustPath[0]))
        {
            // if that validated, we should have a root for this chain now, add it to the custom trust store
            //chain.ChainPolicy.CustomTrustStore.Clear();
            //chain.ChainPolicy.CustomTrustStore.Add(chain.ChainElements[^1].Certificate);

            //// explicitly trust the custom root we just added
            //chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            // if the attestation cert has a CDP extension, go ahead and turn on online revocation checking
            if (!string.IsNullOrEmpty(CDPFromCertificateExts(trustPath[0].Extensions)))
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            
            // don't allow unknown root now that we have a custom root
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // now, verify chain again with all checks turned on
            if (chain.Build(trustPath[0]) || AcceptMathcingUntrustedRoot(chain, chain.ChainElements[chain.ChainElements.Count-1].Certificate))
            {
                // if the chain validates, make sure one of the attestation root certificates is one of the chain elements
                foreach (X509Certificate2 attestationRootCertificate in attestationRootCertificates)
                {
                    // skip the first element, as that is the attestation cert
                    if (chain.ChainElements.Cast<X509ChainElement>()
                        .Skip(1)
                        .Any(x => x.Certificate.Thumbprint.Equals(attestationRootCertificate.Thumbprint, StringComparison.Ordinal)))
                        return true;
                }
            }
        }

        return false;
    }

    public static bool AcceptMathcingUntrustedRoot(X509Chain chain, X509Certificate2 rootCertToTrust)
    {
        if (!chain.ChainStatus.Any(status => status.Status == X509ChainStatusFlags.UntrustedRoot))
            return false;

        foreach (var element in chain.ChainElements)
        {
            foreach (var status in element.ChainElementStatus)
            {
                if (status.Status != X509ChainStatusFlags.UntrustedRoot)
                    continue;

                if (!rootCertToTrust.Thumbprint.Equals(element.Certificate.Thumbprint))
                {
                    return false;
                }
            }
        }

        return true;
    }

    public static byte[] SigFromEcDsaSig(byte[] ecDsaSig, int keySize)
    {
        var decoded = AsnElt.Decode(ecDsaSig);
        var r = decoded.Sub[0].GetOctetString();
        var s = decoded.Sub[1].GetOctetString();

        // .NET requires IEEE P-1363 fixed size unsigned big endian values for R and S
        // ASN.1 requires storing positive integer values with any leading 0s removed
        // Convert ASN.1 format to IEEE P-1363 format 
        // determine coefficient size 

        // common coefficient sizes include: 32, 48, and 64
        var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);

        // Create buffer to copy R into 
        Span<byte> p1363R = coefficientSize <= 64
            ? stackalloc byte[coefficientSize]
            : new byte[coefficientSize];

        if (0x0 == r[0] && (r[1] & (1 << 7)) != 0)
        {
            r.Skip(1).ToArray().CopyTo(p1363R.Slice(coefficientSize - r.Length + 1));
        }
        else
        {
            r.CopyTo(p1363R.Slice(coefficientSize - r.Length));
        }

        // Create byte array to copy S into 
        Span<byte> p1363S = coefficientSize <= 64
            ? stackalloc byte[coefficientSize]
            : new byte[coefficientSize];

        if (0x0 == s[0] && (s[1] & (1 << 7)) != 0)
        {
            s.Skip(1).ToArray().CopyTo(p1363S.Slice(coefficientSize - s.Length + 1));
        }
        else
        {
            s.CopyTo(p1363S.Slice(coefficientSize - s.Length));
        }

        // Concatenate R + S coordinates and return the raw signature
        return DataHelper.Concat(p1363R, p1363S);
    }

    /// <summary>
    /// Convert PEM formated string into byte array.
    /// </summary>
    /// <param name="pemStr">source string.</param>
    /// <returns>output byte array.</returns>
    public static byte[] PemToBytes(string pemStr)
    {
        const string PemStartStr = "-----BEGIN";
        const string PemEndStr = "-----END";
        byte[] retval;
        var lines = pemStr.Split('\n');
        var base64Str = "";
        bool started = false, ended = false;
        var cline = "";
        for (var i = 0; i < lines.Length; i++)
        {
            cline = lines[i].ToUpper();
            if (cline == "")
                continue;
            if (cline.Length > PemStartStr.Length)
            {
                if (!started && cline.Substring(0, PemStartStr.Length) == PemStartStr)
                {
                    started = true;
                    continue;
                }
            }
            if (cline.Length > PemEndStr.Length)
            {
                if (cline.Substring(0, PemEndStr.Length) == PemEndStr)
                {
                    ended = true;
                    break;
                }
            }
            if (started)
            {
                base64Str += lines[i];
            }
        }
        if (!(started && ended))
        {
            throw new Exception("'BEGIN'/'END' line is missing.");
        }
        base64Str = base64Str.Replace("\r", "");
        base64Str = base64Str.Replace("\n", "");
        base64Str = base64Str.Replace("\n", " ");
        retval = Convert.FromBase64String(base64Str);
        return retval;
    }

    public static string CDPFromCertificateExts(X509ExtensionCollection exts)
    {
        var cdp = "";
        foreach (var ext in exts)
        {
            if (ext.Oid?.Value is "2.5.29.31") // id-ce-CRLDistributionPoints
            {
                var asnData = AsnElt.Decode(ext.RawData);
                var el = asnData.Sub[0].Sub[0].Sub[0].Sub[0];
                cdp = Encoding.ASCII.GetString(el.GetOctetString());
            }
        }
        return cdp;
    }

    public static bool IsCertInCRL(byte[] crl, X509Certificate2 cert)
    {
        var asnData = AsnElt.Decode(crl);

        if (7 > asnData.Sub[0].Sub.Length)
            return false; // empty CRL

        var revokedCertificates = asnData.Sub[0].Sub[5].Sub;
        var revoked = new List<long>();

        foreach (AsnElt s in revokedCertificates)
        {
            revoked.Add(BitConverter.ToInt64(s.Sub[0].GetOctetString().Reverse().ToArray(), 0)); // reverse -> convert to big-endian order
        }

        return revoked.Contains(BitConverter.ToInt64(cert.GetSerialNumber(), 0));
    }
}
