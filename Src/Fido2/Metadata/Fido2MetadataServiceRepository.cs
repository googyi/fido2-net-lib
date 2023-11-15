using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Text;
using System.Collections.Generic;

namespace Fido2NetLib;

public sealed class Fido2MetadataServiceRepository : IMetadataRepository
{
    private ReadOnlySpan<byte> ROOT_CERT =>
        "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G"u8 +
        "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp"u8 +
        "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4"u8 +
        "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG"u8 +
        "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI"u8 +
        "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8"u8 +
        "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT"u8 +
        "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm"u8 +
        "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd"u8 +
        "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ"u8 +
        "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw"u8 +
        "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o"u8 +
        "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU"u8 +
        "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp"u8 +
        "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK"u8 +
        "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX"u8 +
        "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs"u8 +
        "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH"u8 +
        "WD9f"u8;

    private readonly string _blobUrl = "https://mds3.fidoalliance.org/";
    private readonly IHttpClientFactory _httpClientFactory;

    public Fido2MetadataServiceRepository(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<MetadataStatement>(entry.MetadataStatement);
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        var rawBLOB = await GetRawBlobAsync();
        return await DeserializeAndValidateBlobAsync(rawBLOB, cancellationToken);
    }

    private async Task<string> GetRawBlobAsync()
    {
        var url = _blobUrl;
        return await DownloadStringAsync(url);
    }

    private async Task<string> DownloadStringAsync(string url)
    {
        return await _httpClientFactory
            .CreateClient(nameof(Fido2MetadataServiceRepository))
            .GetStringAsync(url);
    }

    private async Task<byte[]> DownloadDataAsync(string url)
    {
        return await _httpClientFactory
            .CreateClient(nameof(Fido2MetadataServiceRepository))
            .GetByteArrayAsync(url);
    }

    private X509Certificate2 GetX509Certificate(string certString)
    {
        try
        {
            var certBytes = Convert.FromBase64String(certString);
            return new X509Certificate2(certBytes);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("Could not parse X509 certificate.", ex);
        }
    }

    private async Task<MetadataBLOBPayload> DeserializeAndValidateBlobAsync(string rawBLOBJwt, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(rawBLOBJwt))
            throw new ArgumentNullException(nameof(rawBLOBJwt));

        var jwtParts = rawBLOBJwt.Split('.');

        if (jwtParts.Length != 3)
            throw new ArgumentException("The JWT does not have the 3 expected components");

        var blobHeaderString = jwtParts.First();
        var blobHeader = JObject.Parse(Encoding.UTF8.GetString(Base64Url.Decode(blobHeaderString)));

        string blobAlg = blobHeader["alg"]?.Value<string>();

        if (blobAlg == null)
            throw new Fido2MetadataException("No alg value was present in the BLOB header");

        var x5cArray = blobHeader["x5c"] as JArray;

        if (x5cArray == null)
            throw new Fido2MetadataException("No x5c value was present in the BLOB header");

        var keyStrings = x5cArray.Values<string>().ToList();

        if (keyStrings.Count == 0)
        {
            throw new Fido2MetadataException("No x5c keys were present in the BLOB header");
        }

        var rootCert = X509CertificateHelper.CreateFromBase64String(ROOT_CERT);
        var blobCerts = keyStrings.Select(o => GetX509Certificate(o)).ToArray();
        var keys = new List<SecurityKey>();

        foreach (var certString in keyStrings)
        {
            var cert = GetX509Certificate(certString);

            if (cert.GetECDsaPublicKey() is ECDsa ecdsaPublicKey)
            {
                keys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
            }
            else if (cert.GetRSAPublicKey() is RSA rsaPublicKey)
            {
                keys.Add(new RsaSecurityKey(rsaPublicKey));
            }
            else
            {
                throw new Fido2MetadataException("Unknown certificate algorithm");
            }
        }
        var blobPublicKeys = keys.ToArray(); // defensive copy

        var certChain = new X509Chain();
        certChain.ChainPolicy.ExtraStore.Add(rootCert);
        certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = blobPublicKeys
        };

        var tokenHandler = new JwtSecurityTokenHandler()
        {
            // 250k isn't enough bytes for conformance test tool
            // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1097
            MaximumTokenSizeInBytes = rawBLOBJwt.Length
        };

        tokenHandler.ValidateToken(
            rawBLOBJwt,
            validationParameters,
            out var validatedToken);

        if (blobCerts.Length > 1)
        {
            certChain.ChainPolicy.ExtraStore.AddRange(blobCerts.Skip(1).ToArray());
        }

        var certChainIsValid = certChain.Build(blobCerts[0]);
        // if the root is trusted in the context we are running in, valid should be true here
        if (!certChainIsValid)
        {
            foreach (var element in certChain.ChainElements)
            {
                if (element.Certificate.Issuer != element.Certificate.Subject)
                {
                    var cdp = CryptoUtils.CDPFromCertificateExts(element.Certificate.Extensions);
                    var crlFile = await DownloadDataAsync(cdp);
                    if (CryptoUtils.IsCertInCRL(crlFile, element.Certificate))
                        throw new Fido2VerificationException($"Cert {element.Certificate.Subject} found in CRL {cdp}");
                }
            }

            // otherwise we have to manually validate that the root in the chain we are testing is the root we downloaded
            if (rootCert.Thumbprint == certChain.ChainElements[certChain.ChainElements.Count - 1].Certificate.Thumbprint &&
                // and that the number of elements in the chain accounts for what was in x5c plus the root we added
                certChain.ChainElements.Count == (keyStrings.Count + 1) &&
                // and that the root cert has exactly one status with the value of UntrustedRoot
                certChain.ChainElements[certChain.ChainElements.Count - 1].ChainElementStatus[0].Status == X509ChainStatusFlags.UntrustedRoot)
            {
                // if we are good so far, that is a good sign
                certChainIsValid = true;
                for (var i = 0; i < certChain.ChainElements.Count - 1; i++)
                {
                    // check each non-root cert to verify zero status listed against it, otherwise, invalidate chain
                    if (0 != certChain.ChainElements[i].ChainElementStatus.Length)
                        certChainIsValid = false;
                }
            }
        }

        if (!certChainIsValid)
            throw new Fido2VerificationException("Failed to validate cert chain while parsing BLOB");

        var blobPayload = ((JwtSecurityToken)validatedToken).Payload.SerializeToJson();

        MetadataBLOBPayload blob = JsonConvert.DeserializeObject<MetadataBLOBPayload>(blobPayload);
        blob.JwtAlg = blobAlg;
        return blob;
    }
}
