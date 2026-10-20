using Newtonsoft.Json;

namespace Fido2NetLib.Objects;

/// <summary>
/// This is a dictionary containing the client extension output values for zero or more WebAuthn Extensions
/// </summary>
public sealed class AuthenticationExtensionsClientInputs
{
    /// <summary>
    /// This extension allows for passing of conformance tests
    /// </summary>
    [JsonProperty("example.extension.bool", NullValueHandling = NullValueHandling.Ignore)]
    public bool? Example { get; set; }

    /// <summary>
    /// This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO JavaScript APIs to request an assertion.
    /// https://www.w3.org/TR/webauthn/#sctn-appid-extension
    /// </summary>
    [JsonProperty("appid", NullValueHandling = NullValueHandling.Ignore)]
    [JsonIgnore]
    public string AppID { private get; set; }

    public string GetAppID()
    {
        return AppID;
    }

    /// <summary>
    /// This extension enables the WebAuthn Relying Party to determine which extensions the authenticator supports.
    /// https://www.w3.org/TR/webauthn/#sctn-supported-extensions-extension
    /// </summary>
    [JsonProperty("exts", NullValueHandling = NullValueHandling.Ignore)]
    public bool? Extensions { get; set; }

    /// <summary>
    /// This extension enables use of a user verification method.
    /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
    /// </summary>
    [JsonProperty("uvm", NullValueHandling = NullValueHandling.Ignore)]
    [JsonIgnore]
    public bool? UserVerificationMethod { private get; set; }

#nullable enable
    /// <summary>
    /// This extension enables use of a user verification method.
    /// https://www.w3.org/TR/webauthn/#sctn-uvm-extension
    /// </summary>
    [JsonProperty("devicePubKey", NullValueHandling = NullValueHandling.Ignore)]
    public AuthenticationExtensionsDevicePublicKeyInputs? DevicePubKey { get; set; }

    /// <summary>
    /// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
    /// </summary>
    [JsonProperty("credProps", NullValueHandling = NullValueHandling.Ignore)]
    public bool? CredProps { get; set; }

    /// <summary>
    /// This extension allows a Relying Party to evaluate outputs from a pseudo-random function (PRF) associated with a credential.
    /// https://w3c.github.io/webauthn/#prf-extension
    /// </summary>
    [JsonProperty("prf", NullValueHandling = NullValueHandling.Ignore)]
    public AuthenticationExtensionsPRFInputs? PRF { get; set; }
}

