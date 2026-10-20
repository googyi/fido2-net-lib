using System.Text;

using Fido2NetLib;

namespace fido2_net_lib.Test;

public class Base64UrlTest
{
    [Theory]
    [MemberData(nameof(GetData))]
    public void EncodeAndDecodeResultsAreEqual(byte[] data)
    {
        // Act
        var encodedString = Base64Url.Encode(data);
        var decodedBytes = Base64Url.Decode(encodedString);

        // Assert
        Assert.Equal(data, decodedBytes);
    }

    public static IEnumerable<object[]> GetData()
    {
        return new TestDataGenerator();
    }

    private class TestDataGenerator : TheoryData<byte[]>
    {
        public TestDataGenerator()
        {
            Add(Encoding.UTF8.GetBytes("A").ToArray());
            Add(Encoding.UTF8.GetBytes("This is a string fragment to test Base64Url encoding & decoding.").ToArray());
            Add(Array.Empty<byte>());
        }
    }
}
