using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Fido2NetLib.Internal;

public readonly struct GetBLOBRequest
{
    [JsonConstructor]
    public GetBLOBRequest(string endpoint)
    {
        Endpoint = endpoint;
    }

    [JsonProperty("endpoint")]
    public string Endpoint { get; }
}
