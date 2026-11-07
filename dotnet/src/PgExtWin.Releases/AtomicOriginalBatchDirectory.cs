using System.Text.RegularExpressions;

namespace PgExtWin.Releases;

/// <summary>
/// Common original-ZIP batch transaction used by native and (only after
/// independent authorization) external provider adapters. No admission or
/// signing authority is conveyed by creating or committing a local directory.
/// </summary>
internal sealed class AtomicOriginalBatchDirectory : IDisposable
{
    internal string StageDirectory { get; }
    internal string FinalDirectory { get; }

    internal AtomicOriginalBatchDirectory(string outputParent, string outputName)
    {
        if (!Regex.IsMatch(outputName, @"\A[a-z][a-z0-9-]*\z",
                RegexOptions.CultureInvariant))
            throw new InvalidDataException("Unsafe original-batch output name");
        var parent = Path.GetFullPath(outputParent);
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Batch output parent must already exist");
        for (DirectoryInfo? d = new(parent); d is not null; d = d.Parent)
            if ((d.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Batch output parent contains a link");
        FinalDirectory = Path.Combine(parent, outputName);
        RequireAbsent(parent, outputName);
        StageDirectory = Path.Combine(parent,
            ".pgextwin-batch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(StageDirectory);
    }

    internal string Commit()
    {
        var parent = Path.GetDirectoryName(FinalDirectory)!;
        RequireAbsent(parent, Path.GetFileName(FinalDirectory));
        // Same-volume directory rename is the only public visibility boundary.
        // Never publish a partial collection or overwrite an existing batch.
        Directory.Move(StageDirectory, FinalDirectory);
        return FinalDirectory;
    }

    private static void RequireAbsent(string parent, string name)
    {
        if (Directory.EnumerateFileSystemEntries(parent).Any(x =>
            string.Equals(Path.GetFileName(x), name, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Batch destination already exists; refusing overwrite");
    }

    public void Dispose()
    {
        if (Directory.Exists(StageDirectory))
            Directory.Delete(StageDirectory, recursive: true);
    }
}
