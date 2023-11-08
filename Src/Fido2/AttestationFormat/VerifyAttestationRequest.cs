using System;

using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib;

public sealed class VerifyAttestationRequest
{
    private readonly CBORObject _attStmt;
    private readonly AuthenticatorData _authenticatorData;
    private readonly byte[] _clientDataHash;

    public VerifyAttestationRequest(CBORObject attStmt, AuthenticatorData authenticationData, byte[] clientDataHash)
    {
        _attStmt = attStmt;
        _authenticatorData = authenticationData;
        _clientDataHash = clientDataHash;
    }

    internal CBORObject AttStmt => _attStmt;

    internal ReadOnlySpan<byte> ClientDataHash => _clientDataHash;

    internal CBORObject X5c => _attStmt["x5c"];

    internal CBORObject EcdaaKeyId => _attStmt["ecdaaKeyId"];

    internal AuthenticatorData AuthData => _authenticatorData;

    internal CBORObject CredentialPublicKey => AuthData.AttestedCredentialData!.CredentialPublicKey.GetCborObject();

    internal byte[] Data => DataHelper.Concat(_authenticatorData.ToByteArray(), _clientDataHash);

    internal bool TryGetVer(out string ver)
    {
        if (_attStmt["ver"].Type == CBORType.TextString && _attStmt["ver"].AsString().Length > 0)
        {
            ver = _attStmt["ver"].AsString();

            return true;
        }

        ver = null;

        return false;
    }

    internal bool TryGetAlg(out COSE.Algorithm alg)
    {
        if (_attStmt["alg"] != null && _attStmt["alg"].IsNumber)
        {
            alg = (COSE.Algorithm)_attStmt["alg"].AsInt32();

            return true;
        }

        alg = default;

        return false;
    }

    internal bool TryGetSig(out byte[] sig)
    {
        if (_attStmt["sig"].Type == CBORType.ByteString && _attStmt["sig"].GetByteString().Length > 0)
        {
            sig = _attStmt["sig"].GetByteString();

            return true;
        }

        sig = null;

        return false;
    }
}
