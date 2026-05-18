// Reference canonicalizer using the same API as XmlSignatureBuilder / OPC signing.
// Usage: dotnet run -- <input.xml> [output.bin]
// Writes UTF-8 canonical bytes to stdout if no output path is given.

using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: C14nReference <input.xml> [output.bin]");
    return 1;
}

var inputPath = args[0];
var xml = File.ReadAllText(inputPath);

var doc = new XmlDocument { PreserveWhitespace = true };
doc.LoadXml(xml);

var transform = new XmlDsigC14NTransform(false);
transform.LoadInput(doc);
var stream = (MemoryStream)transform.GetOutput(typeof(Stream))!;
var bytes = stream.ToArray();

if (args.Length >= 2)
{
    File.WriteAllBytes(args[1], bytes);
}
else
{
    Console.OpenStandardOutput().Write(bytes);
}

return 0;
