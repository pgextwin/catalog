using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using PgExtWin.Releases;

// Offline synthetic original bytes only: no HTTP, authentic signed source,
// formal Publisher admission, installation or external download permissions.
internal static class ExternalOriginalZipIntegrityTests
{
    private static byte[] Zip(params (string Name, string Content)[] files)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, body) in files)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8, leaveOpen: false);
                writer.Write(body);
            }
        }
        return output.ToArray();
    }

    private static string Hash(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void Verify(byte[] bytes, long? size = null, string? sha = null) =>
        ExternalOriginalZipIntegrity.Verify(bytes, size ?? bytes.Length, sha ?? Hash(bytes));

    public static void Run(Action<bool, string> check, Action<Action, string> denies)
    {
        var normal = Zip(
            ("oracle_fdw.dll", "synthetic-original-test-binary"),
            ("sql/oracle_fdw--2.9.0.sql", "SELECT 1;"));
        var receipt = ExternalOriginalZipIntegrity.Verify(normal, normal.Length, Hash(normal));
        check(receipt.OriginalBytes == normal.Length &&
              receipt.OriginalSha256 == Hash(normal) && receipt.ArchiveMembers == 2 &&
              receipt.Scope == "INTEGRITY_ONLY_NOT_AUTHORIZED",
              "External original ZIP offline exact byte and member read succeeds without authority");

        denies(() => Verify(normal, normal.Length + 1), "External original ZIP wrong pinned size denied");
        denies(() => Verify(normal, null, new string('0', 64)), "External original ZIP SHA substitution denied");
        denies(() => Verify(normal, null, "ABC"), "External original ZIP invalid digest denied");
        denies(() => Verify(normal, ExternalOriginalZipIntegrity.MaxOriginalBytes + 1),
            "External original ZIP oversized declared original denied");
        var tampered = (byte[])normal.Clone();
        tampered[20] ^= 0x10;
        denies(() => Verify(tampered, null, Hash(normal)), "External original ZIP corrupted original bytes denied");

        var html = Encoding.UTF8.GetBytes("<html>not a zip</html>");
        denies(() => Verify(html), "External original ZIP HTML replacement denied even with matching SHA");
        var broken = Encoding.UTF8.GetBytes("PK\u0003\u0004not-a-real-central-directory");
        denies(() => Verify(broken), "External original ZIP fake local header denied");
        denies(() => Verify(Zip(("../escape.dll", "malicious"))),
            "External original ZIP traversal member denied");
        denies(() => Verify(Zip(("/absolute.dll", "malicious"))),
            "External original ZIP absolute path denied");
        denies(() => Verify(Zip(("path\\escape.dll", "malicious"))),
            "External original ZIP Windows backslash traversal denied");
        denies(() => Verify(Zip(("file:stream", "malicious"))),
            "External original ZIP device/ADS path denied");
        denies(() => Verify(Zip(("SQL/EXT.sql", "a"), ("sql/ext.SQL", "b"))),
            "External original ZIP case-insensitive member collision denied");
        denies(() => Verify(Zip(("directory/", ""))),
            "External original ZIP directory-only payload denied");
        denies(() => Verify(Zip(("a/./b.sql", "a"))),
            "External original ZIP dot-segment path denied");
        check(normal.Length > 4, "External original ZIP positive fixture truly contains bytes");
    }
}
