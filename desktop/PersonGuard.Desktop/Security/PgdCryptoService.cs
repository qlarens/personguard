using System.Buffers.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Storage;

namespace PersonGuard.Desktop.Security;

public sealed class VaultSession : IDisposable
{
    private readonly object _gate = new();
    private ProtectedBytes _vaultKey;
    private KeyEnvelope _envelope;
    private PasskeyEnvelope? _passkey;
    private bool _disposed;

    public VaultSession(ProtectedBytes vaultKey, KeyEnvelope envelope, bool migratedFromV1)
    {
        _vaultKey = vaultKey;
        _envelope = envelope;
        MigratedFromV1 = migratedFromV1;
    }

    public ProtectedBytes VaultKey { get { lock (_gate) return _vaultKey; } }
    public KeyEnvelope Envelope { get { lock (_gate) return _envelope; } }
    public bool MigratedFromV1 { get; }
    public PasskeyEnvelope? Passkey { get { lock (_gate) return _passkey; } set { lock (_gate) _passkey = value; } }

    // One generation of key, envelope and slot: a mixed save would wrap a key that cannot decrypt the data.
    internal (byte[] Key, KeyEnvelope Envelope, PasskeyEnvelope? Passkey) Snapshot()
    {
        lock (_gate) return (_vaultKey.Reveal(), _envelope, _passkey);
    }

    // A new data key: old passwords, removed passkey slots and a leaked key cannot open future saves.
    internal void Rekey(ReadOnlySpan<byte> key, KeyEnvelope envelope)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ProtectedBytes old = _vaultKey;
            _vaultKey = ProtectedBytes.FromBytes(key);
            _envelope = envelope;
            _passkey = null; // The slot wraps the old key.
            old.Dispose();
        }
    }

    public void Dispose()
    {
        lock (_gate) { _disposed = true; _vaultKey.Dispose(); }
    }
}

public sealed record KeyEnvelope(int MemoryKiB, int Iterations, int Parallelism, byte[] Salt, byte[] WrapNonce, byte[] WrappedVaultKey);
public sealed record OpenVaultResult(VaultDocument Vault, VaultSession Session);
public sealed record PasskeyEnvelope(byte[] CredentialId, byte[] Salt, byte[] Nonce, byte[] WrappedKey);

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
        byte[] vaultKey = [];
        byte[] dataNonce = RandomNumberGenerator.GetBytes(12);
        try
        {
            (vaultKey, KeyEnvelope envelope, PasskeyEnvelope? passkey) = session.Snapshot();
            byte[] core = BuildCoreHeader(envelope.MemoryKiB, envelope.Iterations, envelope.Parallelism, envelope.Salt, envelope.WrapNonce);
            byte[] preamble = new byte[PreambleSize];
            core.CopyTo(preamble, 0);
            envelope.WrappedVaultKey.CopyTo(preamble, CoreHeaderSize);
            dataNonce.CopyTo(preamble, CoreHeaderSize + WrappedKeySize);
            byte[] prefix = BuildPasskeyPrefix(passkey);
            byte[] aad = [.. prefix, .. preamble];
            if (plaintext.Length > MaxFileBytes - aad.Length - GcmTagSize)
                throw new InvalidDataException("Сейф превышает безопасный лимит 64 МБ. Сохранение отменено.");
            byte[] encrypted = EncryptAesGcm(vaultKey, dataNonce, plaintext, aad);
            byte[] output = [.. aad, .. encrypted];
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
        if (file[..4].SequenceEqual("PGD3"u8))
        {
            var (slot, offset) = ReadPasskeyHeader(file);
            var result = OpenV2(file[offset..], masterPassword, file[..offset].ToArray());
            result.Session.Passkey = slot;
            return result;
        }
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

    /// <summary>Wraps a fresh data key with <paramref name="newPassword"/> and drops the passkey slot.</summary>
    public static void ChangeMasterPassword(VaultSession session, SecureString newPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] kek = Argon2Kdf.Derive(newPassword, salt, Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism);
        try
        {
            byte[] core = BuildCoreHeader(Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism, salt, nonce);
            byte[] wrapped = EncryptAesGcm(kek, nonce, key, core);
            session.Rekey(key, new KeyEnvelope(Argon2Kdf.VaultMemoryKiB, Argon2Kdf.VaultIterations, Argon2Kdf.VaultParallelism, salt, nonce, wrapped));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private static OpenVaultResult OpenV2(ReadOnlySpan<byte> file, SecureString? masterPassword, byte[]? prefix = null, byte[]? passkeyKey = null)
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
        byte[] preamble = [.. prefix ?? [], .. file[..PreambleSize]];
        byte[] kek = passkeyKey is null ? Argon2Kdf.Derive(masterPassword!, salt, memory, iterations, parallelism) : [];
        byte[]? vaultKey = null;
        byte[]? plaintext = null;
        try
        {
            vaultKey = passkeyKey?.ToArray() ?? DecryptAesGcm(kek, wrapNonce, wrapped, core);
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

    public static PasskeyEnvelope? GetPasskey(ReadOnlySpan<byte> file) =>
        file.Length >= 4 && file[..4].SequenceEqual("PGD3"u8) ? ReadPasskeyHeader(file).Slot : null;

    public static PasskeyEnvelope CreatePasskeyEnvelope(VaultSession session, byte[] credentialId, byte[] salt, byte[] prf)
    {
        if (credentialId.Length is < 1 or > 1024 || salt.Length != 32 || prf.Length != 32)
            throw new InvalidDataException("Некорректные параметры ключа входа.");
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = session.VaultKey.Reveal();
        byte[] kek = DerivePasskeyKey(prf, salt);
        try { return new(credentialId.ToArray(), salt.ToArray(), nonce, EncryptAesGcm(kek, nonce, key, credentialId)); }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(kek); }
    }

    public static OpenVaultResult OpenWithPasskey(ReadOnlySpan<byte> file, byte[] prf)
    {
        if (prf.Length != 32) throw new CryptographicException("Ключ входа не вернул PRF-секрет.");
        var (slot, offset) = ReadPasskeyHeader(file);
        byte[] kek = DerivePasskeyKey(prf, slot.Salt);
        byte[]? key = null;
        try
        {
            key = DecryptAesGcm(kek, slot.Nonce, slot.WrappedKey, slot.CredentialId);
            var result = OpenV2(file[offset..], null, file[..offset].ToArray(), key);
            result.Session.Passkey = slot;
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(kek); if (key is not null) CryptographicOperations.ZeroMemory(key); }
    }

    public static bool VerifyPasskey(VaultSession session, byte[] prf)
    {
        var slot = session.Passkey;
        if (slot is null || prf.Length != 32) return false;
        byte[] kek = DerivePasskeyKey(prf, slot.Salt);
        byte[]? key = null;
        byte[]? expected = null;
        try
        {
            key = DecryptAesGcm(kek, slot.Nonce, slot.WrappedKey, slot.CredentialId);
            expected = session.VaultKey.Reveal();
            return CryptographicOperations.FixedTimeEquals(key, expected);
        }
        catch (CryptographicException) { return false; }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (expected is not null) CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static byte[] DerivePasskeyKey(byte[] prf, byte[] salt) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, prf, 32, salt, "PersonGuard PGD3 passkey wrap v1"u8.ToArray());

    private static byte[] BuildPasskeyPrefix(PasskeyEnvelope? slot)
    {
        if (slot is null) return [];
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(slot);
        byte[] prefix = new byte[8 + json.Length];
        "PGD3"u8.CopyTo(prefix);
        BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(4), json.Length);
        json.CopyTo(prefix, 8);
        return prefix;
    }

    private static (PasskeyEnvelope Slot, int Offset) ReadPasskeyHeader(ReadOnlySpan<byte> file)
    {
        if (file.Length > MaxFileBytes || file.Length < 8 || !file[..4].SequenceEqual("PGD3"u8))
            throw new InvalidDataException("Файл PGD3 повреждён.");
        int length = BinaryPrimitives.ReadInt32BigEndian(file[4..8]);
        if (length is < 1 or > 8192 || file.Length < 8 + length + PreambleSize + GcmTagSize)
            throw new InvalidDataException("Некорректный заголовок PGD3.");
        PasskeyEnvelope slot;
        try { slot = JsonSerializer.Deserialize<PasskeyEnvelope>(file.Slice(8, length)) ?? throw new JsonException(); }
        catch (JsonException) { throw new InvalidDataException("Некорректный ключ входа PGD3."); }
        if (slot.CredentialId is not { Length: >= 1 and <= 1024 } || slot.Salt is not { Length: 32 } ||
            slot.Nonce is not { Length: 12 } || slot.WrappedKey is not { Length: 48 } ||
            !file.Slice(8 + length, 4).SequenceEqual(MagicV2))
            throw new InvalidDataException("Некорректные параметры PGD3.");
        return (slot, 8 + length);
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

