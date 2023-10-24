﻿using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

namespace Fido2NetLib;

public sealed class CredentialCreateOptions : Fido2ResponseBase
{
    /// <summary>
    /// 
    /// This member contains data about the Relying Party responsible for the request.
    /// Its value’s name member is required.
    /// Its value’s id member specifies the relying party identifier with which the credential should be associated.If omitted, its value will be the CredentialsContainer object’s relevant settings object's origin's effective domain.
    /// </summary>
    [JsonPropertyName("rp")]
    public PublicKeyCredentialRpEntity Rp { get; set; }

    /// <summary>
    /// This member contains data about the user account for which the Relying Party is requesting attestation. 
    /// Its value’s name, displayName and id members are required.
    /// </summary>
    [JsonPropertyName("user")]
    public Fido2User User { get; set; }

    /// <summary>
    /// Must be generated by the Server (Relying Party)
    /// </summary>
    [JsonPropertyName("challenge")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] Challenge { get; set; }

    /// <summary>
    /// This member contains information about the desired properties of the credential to be created. The sequence is ordered from most preferred to least preferred. The platform makes a best-effort to create the most preferred credential that it can.
    /// </summary>
    [JsonPropertyName("pubKeyCredParams")]
    public List<PubKeyCredParam> PubKeyCredParams { get; set; }

    /// <summary>
    /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by the platform.
    /// </summary>
    [JsonPropertyName("timeout")]
    public long Timeout { get; set; }

    /// <summary>
    /// This member is intended for use by Relying Parties that wish to express their preference for attestation conveyance.The default is none.
    /// </summary>
    [JsonPropertyName("attestation")]
    public AttestationConveyancePreference Attestation { get; set; } = AttestationConveyancePreference.None;

    /// <summary>
    /// This member is intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the create() operation.
    /// </summary>
    [JsonPropertyName("authenticatorSelection")]
    public AuthenticatorSelection AuthenticatorSelection { get; set; }

    /// <summary>
    /// This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator.The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    /// </summary>
    [JsonPropertyName("excludeCredentials")]
    public List<PublicKeyCredentialDescriptor> ExcludeCredentials { get; set; }

    /// <summary>
    /// This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsClientInputs Extensions { get; set; }

    public static CredentialCreateOptions Create(Fido2Configuration config, byte[] challenge, Fido2User user, AuthenticatorSelection authenticatorSelection, AttestationConveyancePreference attestationConveyancePreference, List<PublicKeyCredentialDescriptor> excludeCredentials, AuthenticationExtensionsClientInputs extensions)
    {
        return new CredentialCreateOptions
        {
            Status = "ok",
            ErrorMessage = string.Empty,
            Challenge = challenge,
            Rp = new PublicKeyCredentialRpEntity(config.ServerDomain, config.ServerName, config.ServerIcon),
            Timeout = config.Timeout,
            User = user,
            PubKeyCredParams = new List<PubKeyCredParam>(10)
            {
                // Add additional as appropriate
                PubKeyCredParam.Ed25519,
                PubKeyCredParam.ES256,
                PubKeyCredParam.RS256,
                PubKeyCredParam.PS256,
                PubKeyCredParam.ES384,
                PubKeyCredParam.RS384,
                PubKeyCredParam.PS384,
                PubKeyCredParam.ES512,
                PubKeyCredParam.RS512,
                PubKeyCredParam.PS512,
                PubKeyCredParam.RS1,
            },
            AuthenticatorSelection = authenticatorSelection,
            Attestation = attestationConveyancePreference,
            ExcludeCredentials = excludeCredentials ?? new List<PublicKeyCredentialDescriptor>(),
            Extensions = extensions
        };
    }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, FidoModelSerializerContext.Default.CredentialCreateOptions);
    }

    public static CredentialCreateOptions FromJson(string json)
    {
        return JsonSerializer.Deserialize(json, FidoModelSerializerContext.Default.CredentialCreateOptions);
    }
}

#nullable enable

public sealed class PubKeyCredParam
{
    /// <summary>
    /// Constructs a PubKeyCredParam instance
    /// </summary>
    [JsonConstructor]
    public PubKeyCredParam(COSE.Algorithm alg, PublicKeyCredentialType type = PublicKeyCredentialType.PublicKey)
    {
        Type = type;
        Alg = alg;
    }

    /// <summary>
    /// The type member specifies the type of credential to be created.
    /// </summary>
    [JsonPropertyName("type")]
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    /// The alg member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    /// </summary>
    [JsonPropertyName("alg")]
    public COSE.Algorithm Alg { get; }

    public static readonly PubKeyCredParam ES256 = new(COSE.Algorithm.ES256); // External authenticators support the ES256 algorithm
    public static readonly PubKeyCredParam ES384 = new(COSE.Algorithm.ES384);
    public static readonly PubKeyCredParam ES512 = new(COSE.Algorithm.ES512);
    public static readonly PubKeyCredParam RS256 = new(COSE.Algorithm.RS256); // Supported by windows hello
    public static readonly PubKeyCredParam RS384 = new(COSE.Algorithm.RS384);
    public static readonly PubKeyCredParam RS512 = new(COSE.Algorithm.RS512);
    public static readonly PubKeyCredParam PS256 = new(COSE.Algorithm.PS256);
    public static readonly PubKeyCredParam PS384 = new(COSE.Algorithm.PS384);
    public static readonly PubKeyCredParam PS512 = new(COSE.Algorithm.PS512);
    public static readonly PubKeyCredParam Ed25519 = new(COSE.Algorithm.EdDSA);
    public static readonly PubKeyCredParam RS1 = new(COSE.Algorithm.RS1);
}

/// <summary>
/// PublicKeyCredentialRpEntity 
/// </summary>
public sealed class PublicKeyCredentialRpEntity
{
    public PublicKeyCredentialRpEntity(string id, string name, string? icon = null)
    {
        Name = name;
        Id = id;
        Icon = icon;
    }

    /// <summary>
    /// A unique identifier for the Relying Party entity, which sets the RP ID.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; }

    /// <summary>
    /// A human-readable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents:
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("icon")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Icon { get; set; }
}
#nullable disable

/// <summary>
/// WebAuthn Relying Parties may use the AuthenticatorSelectionCriteria dictionary to specify their requirements regarding authenticator attributes.
/// https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection
/// </summary>
public class AuthenticatorSelection
{
    /// <summary>
    /// If this member is present, eligible authenticators are filtered to only authenticators attached with the specified § 5.4.5 Authenticator Attachment Enumeration (enum AuthenticatorAttachment).
    /// </summary>
    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorAttachment? AuthenticatorAttachment { get; set; }

    private ResidentKeyRequirement _residentKey;

    /// <summary>
    /// Specifies the extent to which the Relying Party desires to create a client-side discoverable credential.
    /// For historical reasons the naming retains the deprecated “resident” terminology. 
    /// The value SHOULD be a member of ResidentKeyRequirement but client platforms MUST ignore unknown values, 
    /// treating an unknown value as if the member does not exist. 
    /// If no value is given then the effective value is required if requireResidentKey is true or discouraged if it is false or absent.
    /// </summary>
    [JsonPropertyName("residentKey")]
    public ResidentKeyRequirement ResidentKey
    {
        private get => _residentKey;
        set
        {
            _residentKey = value;
            _requireResidentKey = value switch
            {
                ResidentKeyRequirement.Required => true,
                ResidentKeyRequirement.Preferred or ResidentKeyRequirement.Discouraged => false,
                _ => throw new NotImplementedException()
            };
        }
    }

    private bool _requireResidentKey;

    /// <summary>
    /// This member describes the Relying Parties' requirements regarding resident credentials. If the parameter is set to true, the authenticator MUST create a client-side-resident public key credential source when creating a public key credential.
    /// </summary>
    [Obsolete("Use property ResidentKey.")]
    [JsonPropertyName("requireResidentKey")]
    public bool RequireResidentKey
    {
        get => _requireResidentKey;
        set
        {
            _requireResidentKey = value;
            _residentKey = value ? ResidentKeyRequirement.Required : ResidentKeyRequirement.Discouraged;
        }
    }

    /// <summary>
    /// This member describes the Relying Party's requirements regarding user verification for the create() operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    /// </summary>
    [JsonPropertyName("userVerification")]
    public UserVerificationRequirement UserVerification { get; set; }

    public static AuthenticatorSelection Default => new AuthenticatorSelection
    {
        AuthenticatorAttachment = null,
        ResidentKey = ResidentKeyRequirement.Discouraged,
        UserVerification = UserVerificationRequirement.Preferred
    };
}

public class Fido2User
{
    /// <summary>
    /// Required. A human-friendly identifier for a user account. 
    /// It is intended only for display, i.e., aiding the user in determining the difference between user accounts with similar displayNames. 
    /// For example, "alexm", "alex.p.mueller@example.com" or "+14255551234". https://w3c.github.io/webauthn/#dictdef-publickeycredentialentity
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; set; }

    /// <summary>
    /// The user handle of the user account entity.
    /// To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id member, not the displayName nor name members
    /// </summary>
    [JsonPropertyName("id")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] Id { get; set; }

    /// <summary>
    /// A human-friendly name for the user account, intended only for display.
    /// For example, "Alex P. Müller" or "田中 倫".
    /// The Relying Party SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
    /// </summary>
    [JsonPropertyName("displayName")]
    public string DisplayName { get; set; }
}
