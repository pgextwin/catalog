namespace PgExtWin.Releases;

public sealed record ExternalDownloadItem(
    string Name, string Category, string? PgMajor, string Version, string AssetName,
    string License, long Size, string Sha256, bool Latest)
{
    internal bool MatchesMajor(string selection) =>
        selection == "all" || PgMajor is null || PgMajor == selection;
}
