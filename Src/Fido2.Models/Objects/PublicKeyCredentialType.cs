using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Fido2NetLib.Objects;

/// <summary>
/// PublicKeyCredentialType.
/// https://www.w3.org/TR/webauthn-2/#enum-credentialType
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum PublicKeyCredentialType
{
    [EnumMember(Value = "public-key")]
    PublicKey,

    [EnumMember(Value = "invalid")]
    Invalid
}
