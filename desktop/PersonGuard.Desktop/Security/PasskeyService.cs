using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PersonGuard.Desktop.Security;

// ABI follows microsoft/webauthn webauthn.h. No browser, server or Apple account token is used.
public static class PasskeyService
{
    // Stable application namespace; changing this makes existing credentials inaccessible.
    public const string RpId = "personguard.local";
    public static bool IsAvailable
    {
        get { try { return WebAuthNGetApiVersionNumber() >= 6; } catch (DllNotFoundException) { return false; } catch (EntryPointNotFoundException) { return false; } }
    }

    public static byte[] Register(nint owner)
    {
        EnsureAvailable();
        using var memory = new NativeMemoryScope();
        string account = "Сейф " + Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var rp = new Rp { Version = 1, Id = memory.String(RpId), Name = memory.String("PersonGuard") };
        var user = new User { Version = 1, IdLength = 32, Id = memory.Bytes(RandomNumberGenerator.GetBytes(32)), Name = memory.String(account), DisplayName = memory.String(account) };
        var parameter = new Parameter { Version = 1, Type = memory.String("public-key"), Algorithm = -7 };
        var parameters = new List { Count = 1, Items = memory.Struct(parameter) };
        var client = Client(memory, "webauthn.create");
        var options = new MakeOptions { Version = 6, Timeout = 120000, Resident = 1, Verification = 1, Attestation = 1, EnablePrf = 1 };
        nint result = 0;
        try
        {
            Check(WebAuthNAuthenticatorMakeCredential(owner, ref rp, ref user, ref parameters, ref client, ref options, out result));
            if (result == 0 || Marshal.ReadInt32(result) < 5) throw UnsupportedPrf();
            var attestation = Marshal.PtrToStructure<Attestation>(result);
            if (attestation.PrfEnabled == 0) throw UnsupportedPrf();
            return Copy(attestation.CredentialId, attestation.CredentialIdLength, 1024);
        }
        finally { if (result != 0) WebAuthNFreeCredentialAttestation(result); }
    }

    public static byte[] Evaluate(nint owner, byte[] credentialId, byte[] salt)
    {
        EnsureAvailable();
        if (credentialId.Length is < 1 or > 1024 || salt.Length != 32) throw new InvalidDataException("Некорректный ключ входа.");
        using var memory = new NativeMemoryScope();
        var credential = new Credential { Version = 1, IdLength = (uint)credentialId.Length, Id = memory.Bytes(credentialId), Type = memory.String("public-key") };
        var salts = new Salt { FirstLength = 32, First = memory.Bytes(salt) };
        var values = new SaltValues { Global = memory.Struct(salts) };
        var options = new GetOptions { Version = 6, Timeout = 120000, Verification = 1,
            Credentials = new List { Count = 1, Items = memory.Struct(credential) }, SaltValues = memory.Struct(values) };
        var client = Client(memory, "webauthn.get");
        nint result = 0;
        try
        {
            Check(WebAuthNAuthenticatorGetAssertion(owner, RpId, ref client, ref options, out result));
            if (result == 0 || Marshal.ReadInt32(result) < 3) throw UnsupportedPrf();
            var assertion = Marshal.PtrToStructure<Assertion>(result);
            byte[] id = Copy(assertion.Credential.Id, assertion.Credential.IdLength, 1024);
            byte[] auth = Copy(assertion.AuthData, assertion.AuthDataLength, 65536);
            if (!id.AsSpan().SequenceEqual(credentialId) || auth.Length < 37 || (auth[32] & 5) != 5 ||
                !CryptographicOperations.FixedTimeEquals(auth.AsSpan(0, 32), SHA256.HashData(Encoding.UTF8.GetBytes(RpId))))
                throw new CryptographicException("Ключ входа не подтвердил пользователя или приложение.");
            if (assertion.Secret == 0) throw UnsupportedPrf();
            var secret = Marshal.PtrToStructure<Salt>(assertion.Secret);
            if (secret.FirstLength != 32 || secret.First == 0) throw UnsupportedPrf();
            byte[] output = Copy(secret.First, 32, 32);
            // Windows owns the assertion allocation; clear the secret before releasing it.
            Marshal.Copy(new byte[32], 0, secret.First, 32);
            return output;
        }
        finally { if (result != 0) WebAuthNFreeAssertion(result); }
    }

    private static ClientData Client(NativeMemoryScope memory, string type)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(new { type, challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_'), origin = "https://" + RpId, crossOrigin = false });
        return new() { Version = 1, Length = (uint)json.Length, Json = memory.Bytes(json), Hash = memory.String("SHA-256") };
    }
    private static InvalidDataException UnsupportedPrf() => new("Провайдер ключа входа не вернул PRF-секрет. Выберите другой провайдер или откройте сейф мастер-паролем.");
    private static void EnsureAvailable() { if (!IsAvailable) throw new InvalidDataException("Для ключей входа с PRF требуется обновлённая Windows 11 (WebAuthn API 6 или новее)."); }
    private static void Check(int status)
    {
        if (status == 0) return;
        string name = Marshal.PtrToStringUni(WebAuthNGetErrorName(status)) ?? "WebAuthn";
        throw new InvalidDataException($"Операция ключа входа отменена или недоступна ({name}). Можно использовать мастер-пароль.");
    }
    private static byte[] Copy(nint pointer, uint length, int max)
    {
        if (pointer == 0 || length == 0 || length > max) throw new InvalidDataException("Некорректный ответ WebAuthn.");
        byte[] data = new byte[(int)length]; Marshal.Copy(pointer, data, 0, data.Length); return data;
    }

    private sealed class NativeMemoryScope : IDisposable
    {
        private readonly System.Collections.Generic.List<(nint Pointer, int Length)> allocations = [];
        public nint Bytes(byte[] value) { nint p = Marshal.AllocHGlobal(value.Length); allocations.Add((p, value.Length)); Marshal.Copy(value, 0, p, value.Length); return p; }
        public nint String(string value) => Bytes(Encoding.Unicode.GetBytes(value + '\0'));
        public nint Struct<T>(T value) where T : struct { int size = Marshal.SizeOf<T>(); nint p = Marshal.AllocHGlobal(size); allocations.Add((p, size)); Marshal.StructureToPtr(value, p, false); return p; }
        public void Dispose() { foreach (var (p, size) in allocations) { Marshal.Copy(new byte[size], 0, p, size); Marshal.FreeHGlobal(p); } }
    }

    [StructLayout(LayoutKind.Sequential)] private struct List { public uint Count; public nint Items; }
    [StructLayout(LayoutKind.Sequential)] private struct Rp { public uint Version; public nint Id, Name, Icon; }
    [StructLayout(LayoutKind.Sequential)] private struct User { public uint Version, IdLength; public nint Id, Name, Icon, DisplayName; }
    [StructLayout(LayoutKind.Sequential)] private struct Parameter { public uint Version; public nint Type; public int Algorithm; }
    [StructLayout(LayoutKind.Sequential)] private struct ClientData { public uint Version, Length; public nint Json, Hash; }
    [StructLayout(LayoutKind.Sequential)] private struct Credential { public uint Version, IdLength; public nint Id, Type; }
    [StructLayout(LayoutKind.Sequential)] private struct Salt { public uint FirstLength; public nint First; public uint SecondLength; public nint Second; }
    [StructLayout(LayoutKind.Sequential)] private struct SaltValues { public nint Global; public uint Count; public nint Items; }
    [StructLayout(LayoutKind.Sequential)] private struct MakeOptions
    {
        public uint Version, Timeout; public List Credentials, Extensions; public uint Attachment;
        public int Resident; public uint Verification, Attestation, Flags; public nint Cancellation, Exclude;
        public uint Enterprise, LargeBlob; public int PreferResident, Private, EnablePrf;
    }
    [StructLayout(LayoutKind.Sequential)] private struct GetOptions
    {
        public uint Version, Timeout; public List Credentials, Extensions; public uint Attachment, Verification, Flags;
        public nint AppId, UsedAppId, Cancellation, Allow; public uint BlobOperation, BlobLength; public nint Blob, SaltValues; public int Private;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Attestation
    {
        public uint Version; public nint Format; public uint AuthLength; public nint Auth;
        public uint AttestationLength; public nint AttestationData; public uint DecodeType; public nint Decode;
        public uint ObjectLength; public nint Object; public uint CredentialIdLength; public nint CredentialId;
        public List Extensions; public uint Transport; public int Enterprise, LargeBlob, Resident, PrfEnabled;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Assertion
    {
        public uint Version, AuthDataLength; public nint AuthData; public uint SignatureLength; public nint Signature;
        public Credential Credential; public uint UserLength; public nint User; public List Extensions;
        public uint BlobLength; public nint Blob; public uint BlobStatus; public nint Secret;
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("webauthn.dll", ExactSpelling = true)] private static extern uint WebAuthNGetApiVersionNumber();
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("webauthn.dll", ExactSpelling = true)] private static extern int WebAuthNAuthenticatorMakeCredential(nint owner, ref Rp rp, ref User user, ref List parameters, ref ClientData client, ref MakeOptions options, out nint result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("webauthn.dll", ExactSpelling = true, CharSet = CharSet.Unicode)] private static extern int WebAuthNAuthenticatorGetAssertion(nint owner, string rpId, ref ClientData client, ref GetOptions options, out nint result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("webauthn.dll", ExactSpelling = true)] private static extern void WebAuthNFreeCredentialAttestation(nint result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("webauthn.dll", ExactSpelling = true)] private static extern void WebAuthNFreeAssertion(nint result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("webauthn.dll", ExactSpelling = true)] private static extern nint WebAuthNGetErrorName(int status);
}
