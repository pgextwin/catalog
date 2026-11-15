using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace PgExtWin.Releases;

/// <summary>
/// OS-native staging protection combining retained file handles, exclusive
/// share mode, volume/file-ID and hardlink verification, reparse-point
/// rejection, and owner-restricted ACL/mode enforcement.
/// </summary>
internal static class AtomicStageGuard
{
    internal readonly record struct FileIdentity(ulong VolumeId, ulong FileId, uint LinkCount);

    internal sealed record StagedFileExpectation(
        long ExpectedBytes,
        FileStream Stream,
        FileIdentity Identity);

    internal static StringComparer PathComparer =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private const UnixFileMode OwnerDirRwMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerDirLockedMode =
        UnixFileMode.UserRead | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerFileLockedMode =
        UnixFileMode.UserRead;
    private const UnixFileMode OwnerFileRwMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static void RequireNoReparsePointsInAncestors(string directory)
    {
        for (DirectoryInfo? current = new(Path.GetFullPath(directory));
             current is not null;
             current = current.Parent)
        {
            RequireNotReparsePoint(current.FullName, isDirectory: true);
        }
    }

    internal static void InitializeStageDirectory(string stageDirectory)
    {
        RequireNotReparsePoint(stageDirectory, isDirectory: true);
        if (OperatingSystem.IsWindows())
            SetWindowsDirectoryAcl(stageDirectory, FileSystemRights.FullControl, inheritToChildren: true);
        else
            File.SetUnixFileMode(stageDirectory, OwnerDirRwMode);
    }

    internal static void EnsureOwnerOnlyDirectory(string directory)
    {
        RequireNotReparsePoint(directory, isDirectory: true);
        if (OperatingSystem.IsWindows())
            VerifyWindowsDirectoryAcl(directory, isStageRoot: false, locked: false);
        else
        {
            var mode = File.GetUnixFileMode(directory);
            if ((mode & ~OwnerDirRwMode) != 0)
            {
                // Newly created subdirectories under a 0700 parent may inherit a permissive umask;
                // restrict to 0700 immediately if not yet locked, or reject unexpected group/other bits
                // after creation if already observed. Wait: setting 0700 right after CreateDirectory
                // ensures umask never exposes group/other bits.
                File.SetUnixFileMode(directory, OwnerDirRwMode);
            }
        }
    }

    internal static void CreateOwnerOnlySubdirectory(string stageRoot, string subDirectory)
    {
        var fullRoot = Path.GetFullPath(stageRoot);
        var fullSub = Path.GetFullPath(subDirectory);
        // Walk and create each segment from stageRoot down so no intermediate
        // segment is created with loose permissions or follows a reparse point.
        var relative = Path.GetRelativePath(fullRoot, fullSub);
        var current = fullRoot;
        foreach (var part in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (string.IsNullOrEmpty(part) || part == ".")
                continue;
            current = Path.Combine(current, part);
            if (!Directory.Exists(current))
            {
                if (File.Exists(current))
                    throw new InvalidDataException("Stage subdirectory collides with existing file");
                Directory.CreateDirectory(current);
                if (OperatingSystem.IsWindows())
                    SetWindowsDirectoryAcl(current, FileSystemRights.FullControl, inheritToChildren: true);
                else
                    File.SetUnixFileMode(current, OwnerDirRwMode);
            }
            RequireNotReparsePoint(current, isDirectory: true);
            VerifyDirectoryAcl(current, isStageRoot: false, locked: false);
        }
    }

    internal static void LockStagedFile(string filePath)
    {
        RequireNotReparsePoint(filePath, isDirectory: false);
        if (OperatingSystem.IsWindows())
            SetWindowsFileReadOnlyAcl(filePath);
        else
            File.SetUnixFileMode(filePath, OwnerFileLockedMode);
    }

    internal static (FileStream Stream, FileIdentity Identity) OpenAndVerifyIdentity(
        string filePath, string stageRoot)
    {
        var fullFile = Path.GetFullPath(filePath);
        var fullRoot = Path.GetFullPath(stageRoot);
        for (DirectoryInfo? dir = new FileInfo(fullFile).Directory;
             dir is not null;
             dir = dir.Parent)
        {
            RequireNotReparsePoint(dir.FullName, isDirectory: true);
            if (PathComparer.Equals(dir.FullName, fullRoot))
                break;
        }
        RequireNotReparsePoint(fullFile, isDirectory: false);
        VerifyFileAcl(fullFile);

        var stream = new FileStream(
            fullFile,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None,
            bufferSize: 81920,
            FileOptions.SequentialScan);
        try
        {
            var handleIdentity = GetHandleIdentity(stream.SafeFileHandle);
            if (handleIdentity.LinkCount != 1)
                throw new InvalidDataException("Hardlinked staged ZIP rejected");
            var pathIdentity = GetPathIdentity(fullFile, isDirectory: false);
            if (pathIdentity.LinkCount != 1 ||
                pathIdentity.VolumeId != handleIdentity.VolumeId ||
                pathIdentity.FileId != handleIdentity.FileId)
                throw new InvalidDataException("Staged ZIP file identity changed during open");
            if (OperatingSystem.IsWindows())
                VerifyWindowsHandleFinalPathMatches(stream.SafeFileHandle, fullFile);
            VerifyFileAcl(fullFile);
            return (stream, handleIdentity);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    internal static void LockStageDirectoriesForCommit(
        string stageRoot, IEnumerable<string> subDirectories)
    {
        var ordered = subDirectories
            .Select(Path.GetFullPath)
            .Distinct(PathComparer)
            .OrderByDescending(static p => p.Length)
            .ToArray();

        foreach (var dir in ordered)
        {
            RequireNotReparsePoint(dir, isDirectory: true);
            if (OperatingSystem.IsWindows())
                SetWindowsDirectoryAcl(dir,
                    FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                    inheritToChildren: false);
            else
                File.SetUnixFileMode(dir, OwnerDirLockedMode);
        }

        var fullRoot = Path.GetFullPath(stageRoot);
        RequireNotReparsePoint(fullRoot, isDirectory: true);
        if (OperatingSystem.IsWindows())
            SetWindowsDirectoryAcl(fullRoot,
                FileSystemRights.ReadAndExecute | FileSystemRights.Delete | FileSystemRights.Synchronize,
                inheritToChildren: false);
        else
            File.SetUnixFileMode(fullRoot, OwnerDirLockedMode);
    }

    internal static void VerifyStageTreeAndIdentities(
        string stageRoot,
        string outputParent,
        IReadOnlyDictionary<string, StagedFileExpectation> expectedFiles,
        IReadOnlySet<string> expectedDirectories,
        bool directoriesLocked,
        bool verifyOpenHandles)
    {
        RequireNoReparsePointsInAncestors(outputParent);
        var fullRoot = Path.GetFullPath(stageRoot);
        if (!Directory.Exists(fullRoot))
            throw new DirectoryNotFoundException("Atomic batch stage directory disappeared");
        RequireNotReparsePoint(fullRoot, isDirectory: true);
        VerifyDirectoryAcl(fullRoot, isStageRoot: true, locked: directoriesLocked);

        var seenDirectories = new HashSet<string>(PathComparer);
        var seenFiles = new HashSet<string>(PathComparer);
        var queue = new Queue<string>();
        queue.Enqueue(fullRoot);

        var options = new EnumerationOptions
        {
            AttributesToSkip = 0,
            IgnoreInaccessible = false,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false
        };

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos("*", options))
            {
                bool isDir = entry is DirectoryInfo;
                RequireNotReparsePoint(entry.FullName, isDirectory: isDir);

                if (isDir)
                {
                    if (!expectedDirectories.Contains(entry.FullName))
                        throw new InvalidDataException("Unexpected directory in atomic batch stage");
                    if (!seenDirectories.Add(entry.FullName))
                        throw new InvalidDataException("Duplicate directory in atomic batch stage");
                    VerifyDirectoryAcl(entry.FullName, isStageRoot: false, locked: directoriesLocked);
                    queue.Enqueue(entry.FullName);
                }
                else if (entry is FileInfo file)
                {
                    if (!expectedFiles.TryGetValue(file.FullName, out var expectation))
                        throw new InvalidDataException("Unexpected extra file in atomic batch stage");
                    if (!seenFiles.Add(file.FullName))
                        throw new InvalidDataException("Duplicate file in atomic batch stage");
                    VerifyFileAcl(file.FullName);
                    if (file.Length != expectation.ExpectedBytes)
                        throw new InvalidDataException("Staged ZIP byte length changed before commit");
                    var pathIdentity = GetPathIdentity(file.FullName, isDirectory: false);
                    if (pathIdentity.LinkCount != 1 ||
                        pathIdentity.VolumeId != expectation.Identity.VolumeId ||
                        pathIdentity.FileId != expectation.Identity.FileId)
                        throw new InvalidDataException("Staged ZIP volume/file ID mismatch before commit");
                    if (verifyOpenHandles)
                    {
                        var handle = expectation.Stream.SafeFileHandle;
                        if (handle.IsClosed || handle.IsInvalid)
                            throw new InvalidDataException("Held staged ZIP handle became invalid");
                        var handleIdentity = GetHandleIdentity(handle);
                        if (handleIdentity.LinkCount != 1 ||
                            handleIdentity.VolumeId != expectation.Identity.VolumeId ||
                            handleIdentity.FileId != expectation.Identity.FileId)
                            throw new InvalidDataException("Held staged ZIP handle identity changed");
                        if (OperatingSystem.IsWindows())
                            VerifyWindowsHandleFinalPathMatches(handle, file.FullName);
                    }
                }
                else
                {
                    throw new InvalidDataException("Unknown entry type in atomic batch stage");
                }
            }
        }

        if (seenDirectories.Count != expectedDirectories.Count ||
            seenFiles.Count != expectedFiles.Count)
            throw new InvalidDataException("Staged original ZIP or directory missing before commit");
    }

    internal static void RestoreWritablePermissions(string rootDirectory, bool writableFiles)
    {
        if (!Directory.Exists(rootDirectory))
            return;

        // Walk top-down to unlock directories first without following reparse points.
        var queue = new Queue<string>();
        var fullRoot = Path.GetFullPath(rootDirectory);
        if (!IsReparsePointFast(fullRoot))
        {
            RestoreDirectoryPermissionsSingle(fullRoot);
            queue.Enqueue(fullRoot);
        }

        var options = new EnumerationOptions
        {
            AttributesToSkip = 0,
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false
        };

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            IEnumerable<FileSystemInfo> entries;
            try { entries = new DirectoryInfo(current).EnumerateFileSystemInfos("*", options); }
            catch { continue; }

            foreach (var entry in entries)
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                    continue;
                if (entry is DirectoryInfo)
                {
                    RestoreDirectoryPermissionsSingle(entry.FullName);
                    queue.Enqueue(entry.FullName);
                }
                else if (entry is FileInfo && writableFiles)
                {
                    RestoreFilePermissionsSingle(entry.FullName);
                }
            }
        }
    }

    private static bool IsReparsePointFast(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                return true;
            if (OperatingSystem.IsLinux())
                return IsLinuxSymlink(path);
            return false;
        }
        catch { return false; }
    }

    private static void RestoreDirectoryPermissionsSingle(string directory)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                SetWindowsDirectoryAcl(directory, FileSystemRights.FullControl, inheritToChildren: false);
            else
                File.SetUnixFileMode(directory, OwnerDirRwMode);
        }
        catch { /* Best-effort cleanup/post-commit restoration */ }
    }

    private static void RestoreFilePermissionsSingle(string file)
    {
        try
        {
            var attrs = File.GetAttributes(file);
            if ((attrs & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(file, attrs & ~FileAttributes.ReadOnly);
            if (OperatingSystem.IsWindows())
                SetWindowsFileFullControlAcl(file);
            else
                File.SetUnixFileMode(file, OwnerFileRwMode);
        }
        catch { /* Best-effort cleanup/post-commit restoration */ }
    }

    private static void RequireNotReparsePoint(string path, bool isDirectory)
    {
        FileAttributes attrs = File.GetAttributes(path);
        if ((attrs & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse point or symbolic link detected in atomic batch path");
        if (OperatingSystem.IsWindows())
        {
            var info = GetWindowsPathInfo(path, isDirectory);
            if ((info.FileAttributes & FileAttributeReparsePoint) != 0)
                throw new InvalidDataException("Windows reparse point detected in atomic batch path");
        }
        else if (OperatingSystem.IsLinux())
        {
            var stx = StatxPath(path);
            if ((stx.Mode & PosixSIfmtMask) == PosixSIfLnk)
                throw new InvalidDataException("Symbolic link detected in atomic batch path");
        }
    }

    private static void VerifyFileAcl(string filePath)
    {
        if (OperatingSystem.IsWindows())
            VerifyWindowsFileAcl(filePath);
        else
        {
            var mode = File.GetUnixFileMode(filePath);
            if (mode != OwnerFileLockedMode)
                throw new InvalidDataException("Staged ZIP file permission anomaly");
            if (OperatingSystem.IsLinux())
            {
                var stx = StatxPath(filePath);
                if (stx.Uid != LinuxGetEffectiveUid())
                    throw new InvalidDataException("Staged ZIP owner UID mismatch");
            }
        }
    }

    private static void VerifyDirectoryAcl(string directory, bool isStageRoot, bool locked)
    {
        if (OperatingSystem.IsWindows())
            VerifyWindowsDirectoryAcl(directory, isStageRoot, locked);
        else
        {
            var expectedMode = locked ? OwnerDirLockedMode : OwnerDirRwMode;
            var mode = File.GetUnixFileMode(directory);
            if (mode != expectedMode)
                throw new InvalidDataException("Stage directory permission anomaly");
            if (OperatingSystem.IsLinux())
            {
                var stx = StatxPath(directory);
                if (stx.Uid != LinuxGetEffectiveUid())
                    throw new InvalidDataException("Stage directory owner UID mismatch");
            }
        }
    }

    private static FileIdentity GetHandleIdentity(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
        {
            var info = GetWindowsHandleInfo(handle);
            if ((info.FileAttributes & FileAttributeReparsePoint) != 0)
                throw new InvalidDataException("Held handle points to a reparse point");
            ulong fileId = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            return new FileIdentity(info.VolumeSerialNumber, fileId, info.NumberOfLinks);
        }
        if (OperatingSystem.IsLinux())
        {
            var stx = StatxHandle(handle);
            if ((stx.Mode & PosixSIfmtMask) != PosixSIfReg)
                throw new InvalidDataException("Held handle is not a regular file");
            ulong vol = ((ulong)stx.DevMajor << 32) | stx.DevMinor;
            return new FileIdentity(vol, stx.Ino, stx.Nlink);
        }
        return new FileIdentity(0, 0, 1);
    }

    private static FileIdentity GetPathIdentity(string path, bool isDirectory)
    {
        if (OperatingSystem.IsWindows())
        {
            var info = GetWindowsPathInfo(path, isDirectory);
            if ((info.FileAttributes & FileAttributeReparsePoint) != 0)
                throw new InvalidDataException("Path points to a reparse point");
            ulong fileId = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            return new FileIdentity(info.VolumeSerialNumber, fileId, info.NumberOfLinks);
        }
        if (OperatingSystem.IsLinux())
        {
            var stx = StatxPath(path);
            uint expectedType = isDirectory ? PosixSIfDir : PosixSIfReg;
            if ((stx.Mode & PosixSIfmtMask) != expectedType)
                throw new InvalidDataException("Unexpected POSIX file type in stage");
            ulong vol = ((ulong)stx.DevMajor << 32) | stx.DevMinor;
            return new FileIdentity(vol, stx.Ino, stx.Nlink);
        }
        return new FileIdentity(0, 0, 1);
    }

    // ---- Windows Native ACL & FileID/VolumeID P/Invokes ----

    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareAll = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;

    [SupportedOSPlatform("windows")]
    private static FileSystemRights AllowedLockedFileRights =>
        FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    [SupportedOSPlatform("windows")]
    private static FileSystemRights AllowedLockedSubdirRights =>
        FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
    [SupportedOSPlatform("windows")]
    private static FileSystemRights AllowedLockedStageRootRights =>
        FileSystemRights.ReadAndExecute | FileSystemRights.Delete | FileSystemRights.Synchronize;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out ByHandleFileInformation lpFileInformation);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        [Out] char[] lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [SupportedOSPlatform("windows")]
    private static ByHandleFileInformation GetWindowsHandleInfo(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info))
            throw new IOException("GetFileInformationByHandle failed: " + Marshal.GetLastWin32Error());
        return info;
    }

    [SupportedOSPlatform("windows")]
    private static ByHandleFileInformation GetWindowsPathInfo(string path, bool isDirectory)
    {
        uint flags = FileFlagOpenReparsePoint | (isDirectory ? FileFlagBackupSemantics : 0u);
        using var handle = CreateFileW(
            path,
            FileReadAttributes,
            FileShareAll,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (handle.IsInvalid)
            throw new IOException("CreateFileW metadata open failed: " + Marshal.GetLastWin32Error());
        return GetWindowsHandleInfo(handle);
    }

    [SupportedOSPlatform("windows")]
    private static void VerifyWindowsHandleFinalPathMatches(SafeFileHandle handle, string expectedPath)
    {
        var buffer = new char[1024];
        uint len = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (len == 0)
            throw new IOException("GetFinalPathNameByHandleW failed: " + Marshal.GetLastWin32Error());
        if (len >= buffer.Length)
        {
            buffer = new char[len + 1];
            len = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
            if (len == 0 || len >= buffer.Length)
                throw new IOException("GetFinalPathNameByHandleW resized read failed");
        }
        var finalPath = new string(buffer, 0, (int)len);
        var normalizedFinal = finalPath.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? finalPath[4..]
            : finalPath;
        var expectedName = Path.GetFileName(expectedPath);
        var actualName = Path.GetFileName(normalizedFinal);
        if (!string.Equals(expectedName, actualName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Held handle final filename mismatch");

        // Compare parent directory FileID/VolumeID rather than raw path strings to avoid
        // false positives from 8.3 short paths (e.g. RUNNER~1 on Windows CI).
        var expectedDir = Path.GetDirectoryName(Path.GetFullPath(expectedPath))!;
        var actualDir = Path.GetDirectoryName(normalizedFinal)!;
        var expectedDirId = GetPathIdentity(expectedDir, isDirectory: true);
        var actualDirId = GetPathIdentity(actualDir, isDirectory: true);
        if (expectedDirId.VolumeId != actualDirId.VolumeId ||
            expectedDirId.FileId != actualDirId.FileId)
            throw new InvalidDataException("Held handle parent directory identity mismatch");
    }

    [SupportedOSPlatform("windows")]
    private static (SecurityIdentifier UserSid, SecurityIdentifier? OwnerSid) GetCurrentWindowsSids()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new InvalidDataException("Unable to resolve current Windows user SID");
        return (user, identity.Owner);
    }

    [SupportedOSPlatform("windows")]
    private static void SetWindowsDirectoryAcl(
        string directory, FileSystemRights rights, bool inheritToChildren)
    {
        var (userSid, _) = GetCurrentWindowsSids();
        var security = new DirectorySecurity();
        security.SetOwner(userSid);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inheritance = inheritToChildren
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            rights,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void SetWindowsFileReadOnlyAcl(string filePath)
    {
        var (userSid, _) = GetCurrentWindowsSids();
        var security = new FileSecurity();
        security.SetOwner(userSid);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            AllowedLockedFileRights,
            AccessControlType.Allow));
        new FileInfo(filePath).SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void SetWindowsFileFullControlAcl(string filePath)
    {
        var (userSid, _) = GetCurrentWindowsSids();
        var security = new FileSecurity();
        security.SetOwner(userSid);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(filePath).SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void VerifyWindowsFileAcl(string filePath)
    {
        var (userSid, ownerSid) = GetCurrentWindowsSids();
        var security = new FileInfo(filePath).GetAccessControl();
        if (!security.AreAccessRulesProtected)
            throw new InvalidDataException("Staged ZIP ACL protection disabled");
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!owner.Equals(userSid) && (ownerSid is null || !owner.Equals(ownerSid))))
            throw new InvalidDataException("Staged ZIP ACL owner anomaly");
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        bool sawAllow = false;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !userSid.Equals(rule.IdentityReference) ||
                (rule.FileSystemRights & ~AllowedLockedFileRights) != 0 ||
                (rule.FileSystemRights & FileSystemRights.ReadData) == 0)
                throw new InvalidDataException("Staged ZIP ACL anomaly");
            sawAllow = true;
        }
        if (!sawAllow)
            throw new InvalidDataException("Staged ZIP missing owner read ACL");
    }

    [SupportedOSPlatform("windows")]
    private static void VerifyWindowsDirectoryAcl(string directory, bool isStageRoot, bool locked)
    {
        var (userSid, ownerSid) = GetCurrentWindowsSids();
        var security = new DirectoryInfo(directory).GetAccessControl();
        if (!security.AreAccessRulesProtected)
            throw new InvalidDataException("Stage directory ACL protection disabled");
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!owner.Equals(userSid) && (ownerSid is null || !owner.Equals(ownerSid))))
            throw new InvalidDataException("Stage directory ACL owner anomaly");
        var allowedMask = locked
            ? (isStageRoot ? AllowedLockedStageRootRights : AllowedLockedSubdirRights)
            : FileSystemRights.FullControl;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        bool sawAllow = false;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !userSid.Equals(rule.IdentityReference) ||
                (rule.FileSystemRights & ~allowedMask) != 0 ||
                (rule.FileSystemRights & FileSystemRights.ReadData) == 0)
                throw new InvalidDataException("Stage directory ACL anomaly");
            sawAllow = true;
        }
        if (!sawAllow)
            throw new InvalidDataException("Stage directory missing owner ACL");
    }

    // ---- Linux Native statx & UID P/Invokes ----

    private const int AtFdcwd = -100;
    private const int AtSymlinkNoFollow = 0x0100;
    private const int AtEmptyPath = 0x1000;
    private const uint StatxBasicStats = 0x000007ff;
    private const uint PosixSIfmtMask = 0xF000;
    private const uint PosixSIfReg = 0x8000;
    private const uint PosixSIfDir = 0x4000;
    private const uint PosixSIfLnk = 0xA000;

    [StructLayout(LayoutKind.Sequential)]
    private struct StatxTimestamp
    {
        public long TvSec;
        public uint TvNsec;
        public int Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStatx
    {
        public uint Mask;
        public uint BlkSize;
        public ulong Attributes;
        public uint Nlink;
        public uint Uid;
        public uint Gid;
        public ushort Mode;
        public ushort Spare0;
        public ulong Ino;
        public ulong Size;
        public ulong Blocks;
        public ulong AttributesMask;
        public StatxTimestamp Atime;
        public StatxTimestamp Btime;
        public StatxTimestamp Ctime;
        public StatxTimestamp Mtime;
        public uint RdevMajor;
        public uint RdevMinor;
        public uint DevMajor;
        public uint DevMinor;
        public ulong Spare2_00, Spare2_01, Spare2_02, Spare2_03, Spare2_04, Spare2_05, Spare2_06;
        public ulong Spare2_07, Spare2_08, Spare2_09, Spare2_10, Spare2_11, Spare2_12, Spare2_13;
    }

    [SupportedOSPlatform("linux")]
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(
        int dirfd,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname,
        int flags,
        uint mask,
        out LinuxStatx statxbuf);

    [SupportedOSPlatform("linux")]
    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint LinuxGetEffectiveUid();

    [SupportedOSPlatform("linux")]
    private static LinuxStatx StatxPath(string path)
    {
        if (Statx(AtFdcwd, path, AtSymlinkNoFollow, StatxBasicStats, out var buf) != 0)
            throw new IOException("statx path failed: errno=" + Marshal.GetLastPInvokeError());
        return buf;
    }

    [SupportedOSPlatform("linux")]
    private static LinuxStatx StatxHandle(SafeFileHandle handle)
    {
        bool addedRef = false;
        handle.DangerousAddRef(ref addedRef);
        try
        {
            int fd = handle.DangerousGetHandle().ToInt32();
            if (Statx(fd, "", AtEmptyPath, StatxBasicStats, out var buf) != 0)
                throw new IOException("statx handle failed: errno=" + Marshal.GetLastPInvokeError());
            return buf;
        }
        finally
        {
            if (addedRef) handle.DangerousRelease();
        }
    }

    [SupportedOSPlatform("linux")]
    private static bool IsLinuxSymlink(string path)
    {
        if (Statx(AtFdcwd, path, AtSymlinkNoFollow, StatxBasicStats, out var buf) != 0)
            return false;
        return (buf.Mode & PosixSIfmtMask) == PosixSIfLnk;
    }
}
