using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NSec.Cryptography;
using PeterO.Cbor;

namespace Fido2NetLib.Objects;

public sealed class CredentialPublicKey
{
    internal readonly COSE.KeyType _type;
    internal readonly COSE.Algorithm _alg;
    internal readonly CBORObject _cpk;

    public CredentialPublicKey(Stream stream) 
        : this(CBORObject.Read(stream)) { }

    public CredentialPublicKey(byte[] cpk)
        : this(CBORObject.DecodeFromBytes(cpk)) { }

    public CredentialPublicKey(CBORObject cpk)
    {
        _cpk = cpk;
        _type = (COSE.KeyType)cpk[CBORObject.FromObject(COSE.KeyCommonParameter.KeyType)].AsInt32();
        _alg = (COSE.Algorithm)cpk[CBORObject.FromObject(COSE.KeyCommonParameter.Alg)].AsInt32();
    }

    public CredentialPublicKey(ECDsa ecdsaPublicKey, COSE.Algorithm alg)
    {
        _type = COSE.KeyType.EC2;
        _alg = alg;

        var keyParams = ecdsaPublicKey.ExportParameters(false);

        //_cpk = new CborMap
        //{
        //    { COSE.KeyCommonParameter.KeyType, _type },
        //    { COSE.KeyCommonParameter.Alg, _alg },
        //    { COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve() },
        //    { COSE.KeyTypeParameter.X, keyParams.Q.X! },
        //    { COSE.KeyTypeParameter.Y, keyParams.Q.Y! }
        //};

        _cpk = CBORObject.NewMap();
        _cpk.Add(COSE.KeyCommonParameter.KeyType, _type);
        _cpk.Add(COSE.KeyCommonParameter.Alg, alg);
        _cpk.Add(COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve());
        _cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X);
        _cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y);

    }

    public CredentialPublicKey(X509Certificate2 cert, COSE.Algorithm alg)
    {
        //var keyAlg = cert.GetKeyAlgorithm();
        //_type = COSE.GetKeyTypeFromOid(oid: keyAlg);
        //_alg = alg;
        //_cpk = new CborMap
        //{
        //    { COSE.KeyCommonParameter.KeyType, _type },
        //    { COSE.KeyCommonParameter.Alg, _alg }
        //};

        //if (_type is COSE.KeyType.RSA)
        //{
        //    var keyParams = cert.GetRSAPublicKey()!.ExportParameters(false);
        //    _cpk.Add(COSE.KeyTypeParameter.N, keyParams.Modulus!);
        //    _cpk.Add(COSE.KeyTypeParameter.E, keyParams.Exponent!);
        //}
        //else if (_type is COSE.KeyType.EC2)
        //{
        //    var ecDsaPubKey = cert.GetECDsaPublicKey()!;
        //    var keyParams = ecDsaPubKey.ExportParameters(false);

        //    _cpk.Add(COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve());
        //    _cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X!);
        //    _cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y!);
        //}

        var keyAlg = cert.GetKeyAlgorithm();
        _type = COSE.GetKeyTypeFromOid(oid: keyAlg);
        _alg = alg;
        _cpk = CBORObject.NewMap();
        _cpk.Add(COSE.KeyCommonParameter.KeyType, _type);
        _cpk.Add(COSE.KeyCommonParameter.Alg, alg);

        if (COSE.KeyType.RSA == _type)
        {
            var keyParams = cert.GetRSAPublicKey().ExportParameters(false);
            _cpk.Add(COSE.KeyTypeParameter.N, keyParams.Modulus);
            _cpk.Add(COSE.KeyTypeParameter.E, keyParams.Exponent);
        }
        if (COSE.KeyType.EC2 == _type)
        {
            var ecDsaPubKey = cert.GetECDsaPublicKey();
            var keyParams = ecDsaPubKey.ExportParameters(false);

            _cpk.Add(COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve());
            _cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X);
            _cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y);
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        return Verify(data.ToArray(), signature.ToArray());
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        switch (_type)
        {
            case COSE.KeyType.EC2:
                using (ECDsa ecdsa = CreateECDsa())
                {
                    var ecsig = CryptoUtils.SigFromEcDsaSig(signature, ecdsa.KeySize);
                    return ecdsa.VerifyData(data, ecsig, CryptoUtils.HashAlgFromCOSEAlg(_alg));
                }

            case COSE.KeyType.RSA:
                using (RSA rsa = CreateRSA())
                {
                    return rsa.VerifyData(data, signature, CryptoUtils.HashAlgFromCOSEAlg(_alg), Padding);
                }

            case COSE.KeyType.OKP:
                return SignatureAlgorithm.Ed25519.Verify(EdDSAPublicKey, data, signature);
        }
        throw new InvalidOperationException($"Missing or unknown kty {_type}");
    }

    internal RSA CreateRSA()
    {
        if (_type != COSE.KeyType.RSA)
        {
            throw new InvalidOperationException($"Must be a RSA key. Was {_type}");
        }

        var rsa = RSA.Create();
        rsa.ImportParameters(
            new RSAParameters()
            {
                Modulus = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.N)].GetByteString(),
                Exponent = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.E)].GetByteString()
            }
        );

        return rsa; 
    }

    public ECDsa CreateECDsa()
    {
        if (_type != COSE.KeyType.EC2)
        {
            throw new InvalidOperationException($"Must be a EC2 key. Was {_type}");
        }

        var point = new ECPoint
        {
            X = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString(),
            Y = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString(),
        };

        ECCurve curve;

        var crv = (COSE.EllipticCurve)_cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32();

        // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves

        switch ((_alg, crv))
        {
            case (COSE.Algorithm.ES256K, COSE.EllipticCurve.P256K):
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) // see https://github.com/dotnet/runtime/issues/47770
                {
                    throw new PlatformNotSupportedException("The secP256k1 curve is not supported on macOS");
                }

                curve = ECCurve.CreateFromFriendlyName("secP256k1");
                break;
            case (COSE.Algorithm.ES256, COSE.EllipticCurve.P256):
                curve = ECCurve.NamedCurves.nistP256;
                break;
            case (COSE.Algorithm.ES384, COSE.EllipticCurve.P384):
                curve = ECCurve.NamedCurves.nistP384;
                break;
            case (COSE.Algorithm.ES512, COSE.EllipticCurve.P521):
                curve = ECCurve.NamedCurves.nistP521;
                break;
            default:
                throw new InvalidOperationException($"Missing or unknown alg {_alg}");
        }

        return ECDsa.Create(new ECParameters
        {
            Q = point,
            Curve = curve
        });
    }

    internal RSASignaturePadding Padding
    {
        get
        {
            if (_type != COSE.KeyType.RSA)
            {
                throw new InvalidOperationException($"Must be a RSA key. Was {_type}");
            }

            switch (_alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
            {
                case COSE.Algorithm.PS256:
                case COSE.Algorithm.PS384:
                case COSE.Algorithm.PS512:
                    return RSASignaturePadding.Pss;

                case COSE.Algorithm.RS1:
                case COSE.Algorithm.RS256:
                case COSE.Algorithm.RS384:
                case COSE.Algorithm.RS512:
                    return RSASignaturePadding.Pkcs1;
                default:
                    throw new InvalidOperationException($"Missing or unknown alg {_alg}");
            }
        }
    }

    internal NSec.Cryptography.PublicKey EdDSAPublicKey
    {
        get
        {
            if (_type != COSE.KeyType.OKP)
            {
                throw new InvalidOperationException($"Must be a OKP key. Was {_type}");
            }

            switch (_alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
            {
                case COSE.Algorithm.EdDSA:
                    var crv = (COSE.EllipticCurve)_cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32();

                    // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                    if (crv is COSE.EllipticCurve.Ed25519)
                    {
                        return NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString(), KeyBlobFormat.RawPublicKey);
                    }
                    else
                    {
                        throw new InvalidOperationException($"Missing or unknown crv {crv}");
                    }
                default:
                    throw new InvalidOperationException($"Missing or unknown alg {_alg}");
            }
        }
    }

    public byte[] GetBytes() => _cpk.EncodeToBytes();

    public bool IsSameAlg(COSE.Algorithm alg) => _alg.Equals(alg);

    public CBORObject GetCborObject() => _cpk;
}
