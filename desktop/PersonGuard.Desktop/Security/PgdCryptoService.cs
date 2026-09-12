using System.Buffers.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Storage;

namespace PersonGuard.Desktop.Security;

public sealed class VaultSession : IDisposable
{
    public VaultSession(ProtectedBytes vaultKey, KeyEnvelope envelope, bool migratedFromV1)
    {
        VaultKey = vaultKey;
        Envelope = envelope;
        MigratedFromV1 = migratedFromV1;
    }

    public ProtectedBytes VaultKey { get; }
    public KeyEnvelope Envelope { get; private set; }
    public bool MigratedFromV1 { get; }

    public void ReplaceEnvelope(KeyEnvelope envelope) => Envelope = envelope;
    public void Dispose() => VaultKey.Dispose();
}

public sealed record KeyEnvelope(int MemoryKiB, int Iterations, int Parallelism, byte[] Salt, byte[] WrapNonce, byte[] WrappedVaultKey);
public sealed record OpenVaultResult(VaultDocument Vault, VaultSession Session);

public static class PgdCryptoService
{
    private static readonly byte[] MagicV2 = "PGD2"u8.ToArray();
    private static readonly byte[] MagicV1 = "PGD1"u8.ToArray();
    private const int CoreHeaderSize = 48;
    private const int WrappedKeySize = 48;
    private const int PreambleSize = 108;
    private const int GcmTagSize = 16;
    private const int MaxFileBytes = 64 * 1024 * 1024;

    public static VaultSession CreateSession(SecureString masterPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] wrapNonce = RandomNumberGenerator.GetBytes(12);
        byte[] vaultKey = RandomNumberGenerator.GetBytes(32);
        byte[] kek = Argon2Kdf.Derive(masterPassword, salt, Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism);
        try
        {
            byte[] core = BuildCoreHeader(Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism, salt, wrapNonce);
            byte[] wrapped = EncryptAesGcm(kek, wrapNonce, vaultKey, core);
            return new VaultSession(ProtectedBytes.FromBytes(vaultKey), new KeyEnvelope(
                Argon2Kdf.VaultMemoryKiB,
                Argon2Kdf.VaultIterations,
                Argon2Kdf.VaultParallelism,
                salt,
                wrapNonce,
                wrapped), false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    public static byte[] Encrypt(VaultDocument vault, VaultSession session)
    {
        byte[] plaintext = VaultSerializer.Serialize(vault);
        byte[] vaultKey = session.VaultKey.Reveal();
        byte[] dataNonce = RandomNumberGenerator.GetBytes(12);
        try
        {
            byte[] core = BuildCoreHeader(session.Envelope.MemoryKiB, session.Envelope.Iterations, session.Envelope.Parallelism, session.Envelope.Salt, session.Envelope.WrapNonce);
            byte[] preamble = new byte[PreambleSize];
            core.CopyTo(preamble, 0);
            session.Envelope.WrappedVaultKey.CopyTo(preamble, CoreHeaderSize);
            dataNonce.CopyTo(preamble, CoreHeaderSize + WrappedKeySize);
            byte[] encrypted = EncryptAesGcm(vaultKey, dataNonce, plaintext, preamble);
            byte[] output = new byte[preamble.Length + encrypted.Length];
            preamble.CopyTo(output, 0);
            encrypted.CopyTo(output, preamble.Length);
            CryptographicOperations.ZeroMemory(encrypted);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    public static OpenVaultResult Open(ReadOnlySpan<byte> file, SecureString masterPassword)
    {
        if (file.Length > MaxFileBytes) throw new InvalidDataException("Файл превышает безопасный лимит 64 МБ.");
        if (file.Length < 4) throw new InvalidDataException("Файл слишком короткий.");
        if (file[..4].SequenceEqual(MagicV2)) return OpenV2(file, masterPassword);
        if (file[..4].SequenceEqual(MagicV1)) return OpenV1AndMigrate(file, masterPassword);
        throw new InvalidDataException("Это не файл PersonGuard .pgd.");
    }

    public static bool VerifyMasterPassword(VaultSession session, SecureString password)
    {
        byte[] kek = Argon2Kdf.Derive(password, session.Envelope.Salt, session.Envelope.MemoryKiB, session.Envelope.Iterations, session.Envelope.Parallelism);
        byte[]? candidate = null;
        byte[]? expected = null;
        try
        {
            byte[] core = BuildCoreHeader(session.Envelope.MemoryKiB, session.Envelope.Iterations, session.Envelope.Parallelism, session.Envelope.Salt, session.Envelope.WrapNonce);
            candidate = DecryptAesGcm(kek, session.Envelope.WrapNonce, session.Envelope.WrappedVaultKey, core);
            expected = session.VaultKey.Reveal();
            return CryptographicOperations.FixedTimeEquals(candidate, expected);
        }
        catch (CryptographicException) { return false; }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            if (candidate is not null) CryptographicOperations.ZeroMemory(candidate);
            if (expected is not null) CryptographicOperations.ZeroMemory(expected);
        }
    }

    public static void ChangeMasterPassword(VaultSession session, SecureString newPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = session.VaultKey.Reveal();
        byte[] kek = Argon2Kdf.Derive(newPassword, salt, Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism);
        try
        {
            byte[] core = BuildCoreHeader(Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism, salt, nonce);
            byte[] wrapped = EncryptAesGcm(kek, nonce, key, core);
            session.ReplaceEnvelope(new KeyEnvelope(Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism, salt, nonce, wrapped));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private static OpenVaultResult OpenV2(ReadOnlySpan<byte> file, SecureString masterPassword)
    {
        if (file.Length < PreambleSize + GcmTagSize) throw new InvalidDataException("Файл PGD2 повреждён.");
        if (file[4] != 2 || file[5] != 2 || file[6] != 1) throw new InvalidDataException("Версия или алгоритм PGD не поддерживается.");
        int memory = checked((int)BinaryPrimitives.ReadUInt32BigEndian(file.Slice(8, 4)));
        int iterations = checked((int)BinaryPrimitives.ReadUInt32BigEndian(file.Slice(12, 4)));
        int parallelism = checked((int)BinaryPrimitives.ReadUInt32BigEndian(file.Slice(16, 4)));
        if (memory < 19_456 || memory > 524_288 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 8)
            throw new InvalidDataException("Небезопасные или чрезмерные параметры Argon2id.");

        byte[] salt = file.Slice(20, 16).ToArray();
        byte[] wrapNonce = file.Slice(36, 12).ToArray();
        byte[] wrapped = file.Slice(CoreHeaderSize, WrappedKeySize).ToArray();
        byte[] dataNonce = file.Slice(CoreHeaderSize + WrappedKeySize, 12).ToArray();
        byte[] core = file[..CoreHeaderSize].ToArray();
        byte[] preamble = file[..PreambleSize].ToArray();
        byte[] kek = Argon2Kdf.Derive(masterPassword, salt, memory, iterations, parallelism);
        byte[]? vaultKey = null;
        byte[]? plaintext = null;
        try
        {
            vaultKey = DecryptAesGcm(kek, wrapNonce, wrapped, core);
            plaintext = DecryptAesGcm(vaultKey, dataNonce, file[PreambleSize..].ToArray(), preamble);
            VaultDocument vault = VaultSerializer.Deserialize(plaintext);
            var envelope = new KeyEnvelope(memory, iterations, parallelism, salt, wrapNonce, wrapped);
            return new OpenVaultResult(vault, new VaultSession(ProtectedBytes.FromBytes(vaultKey), envelope, false));
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Неверный мастер‑пароль или файл был изменён.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            if (vaultKey is not null) CryptographicOperations.ZeroMemory(vaultKey);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static OpenVaultResult OpenV1AndMigrate(ReadOnlySpan<byte> file, SecureString masterPassword)
    {
        const int oldHeader = 40;
        if (file.Length < oldHeader + GcmTagSize || file[4] != 1 || file[5] != 1 || file[6] != 1)
            throw new InvalidDataException("Файл PGD1 повреждён.");
        int iterations = checked((int)BinaryPrimitives.ReadUInt32BigEndian(file.Slice(8, 4)));
        if (iterations < 100_000 || iterations > 2_000_000) throw new InvalidDataException("Некорректные параметры PGD1.");
        byte[] password = SecureStringUtil.ToUtf8(masterPassword);
        byte[] salt = file.Slice(12, 16).ToArray();
        byte[] nonce = file.Slice(28, 12).ToArray();
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        byte[]? plaintext = null;
        try
        {
            plaintext = DecryptAesGcm(key, nonce, file[oldHeader..].ToArray(), file[..oldHeader].ToArray());
            VaultDocument vault = VaultSerializer.Deserialize(plaintext);
            VaultSession session = CreateSession(masterPassword);
            return new OpenVaultResult(vault, new VaultSession(session.VaultKey, session.Envelope, true));
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Неверный мастер‑пароль или файл был изменён.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            CryptographicOperations.ZeroMemory(key);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] BuildCoreHeader(int memory, int iterations, int parallelism, byte[] salt, byte[] wrapNonce)
    {
        byte[] header = new byte[CoreHeaderSize];
        MagicV2.CopyTo(header, 0);
        header[4] = 2;
        header[5] = 2;
        header[6] = 1;
        header[7] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), checked((uint)memory));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12, 4), checked((uint)iterations));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(16, 4), checked((uint)parallelism));
        salt.CopyTo(header, 20);
        wrapNonce.CopyTo(header, 36);
        return header;
    }

    private static byte[] EncryptAesGcm(byte[] key, byte[] nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        byte[] output = new byte[plaintext.Length + GcmTagSize];
        using var aes = new AesGcm(key, GcmTagSize);
        aes.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length, GcmTagSize), aad);
        return output;
    }

    private static byte[] DecryptAesGcm(byte[] key, byte[] nonce, byte[] ciphertextAndTag, byte[] aad)
    {
        if (ciphertextAndTag.Length < GcmTagSize) throw new CryptographicException("Повреждённая метка GCM.");
        int length = ciphertextAndTag.Length - GcmTagSize;
        byte[] plaintext = new byte[length];
        try
        {
            using var aes = new AesGcm(key, GcmTagSize);
            aes.Decrypt(nonce, ciphertextAndTag.AsSpan(0, length), ciphertextAndTag.AsSpan(length, GcmTagSize), plaintext, aad);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }
}

