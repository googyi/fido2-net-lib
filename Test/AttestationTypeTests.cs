using Newtonsoft.Json;

namespace Fido2NetLib.Objects.Tests;

public class AttestationTypeTests
{
    [Fact]
    public void ImplicitlyConvertibleToString()
    {
        Assert.Equal("none", AttestationType.None);
    }

    [Fact]
    public void CanSerialize()
    {
        Assert.Equal("\"none\"", JsonConvert.SerializeObject(AttestationType.None));
        Assert.Equal("\"ecdaa\"", JsonConvert.SerializeObject(AttestationType.ECDAA));
    }

    [Fact]
    public void CanDeserialize()
    {
        Assert.Equal(AttestationType.None, JsonConvert.DeserializeObject<AttestationType>("\"none\""));
        Assert.Equal(AttestationType.ECDAA, JsonConvert.DeserializeObject<AttestationType>("\"ecdaa\""));
    }
}
