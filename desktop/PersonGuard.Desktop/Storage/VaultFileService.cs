using System.Security.Cryptography;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;

namespace PersonGuard.Desktop.Storage;

public static class VaultFileService
{
    public static async Task<byte[]> ReadAsync(string path, CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Файл не найден.", path);
        if (info.Length > 64L * 1024 * 1024) throw new InvalidDataException("Файл превышает безопасный лимит 64 МБ.");
        return await File.ReadAllBytesAsync(path, cancellationToken);
    }

    public static async Task SaveAtomicAsync(string path, VaultDocument vault, VaultSession session, CancellationToken cancellationToken = default)
    {
        byte[] encrypted = PgdCryptoService.Encrypt(vault, session);
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidOperationException("Не выбрана папка для сохранения.");
        Directory.CreateDirectory(directory);
        string tempPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                await stream.WriteAsync(encrypted, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(fullPath)) File.Move(tempPath, fullPath, overwrite: true);
            else File.Move(tempPath, fullPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }
}
