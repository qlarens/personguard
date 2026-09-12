using System.Security.Cryptography;
using System.Text.Json;
using PersonGuard.Desktop.Models;
using PersonGuard.Desktop.Security;

namespace PersonGuard.Desktop.Storage;

public static class VaultSerializer
{
    public static byte[] Serialize(VaultDocument vault)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", 2);
        writer.WriteString("vaultId", vault.VaultId);
        writer.WriteString("name", vault.Name);
        writer.WriteString("createdAt", vault.CreatedAt);
        writer.WriteString("updatedAt", vault.UpdatedAt);
        writer.WriteStartArray("entries");
        foreach (VaultEntry entry in vault.Entries)
        {
            writer.WriteStartObject();
            writer.WriteString("id", entry.Id);
            writer.WriteString("title", entry.Title);
            writer.WriteString("url", entry.Url);
            writer.WriteString("username", entry.Username);
            writer.WriteString("authProvider", entry.AuthProvider);
            byte[] secret = entry.Password.RevealUtf8();
            try { writer.WriteString("password", secret); }
            finally { CryptographicOperations.ZeroMemory(secret); }
            writer.WriteString("phone", entry.Phone);
            writer.WriteBoolean("favorite", entry.Favorite);
            writer.WriteNumber("strength", entry.Strength);
            writer.WriteString("createdAt", entry.CreatedAt);
            writer.WriteString("updatedAt", entry.UpdatedAt);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();
        return stream.ToArray();
    }

    public static VaultDocument Deserialize(byte[] json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (!root.TryGetProperty("entries", out JsonElement entries) || entries.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Хранилище имеет неверную структуру.");
        if (entries.GetArrayLength() > 100_000)
            throw new InvalidDataException("В хранилище слишком много записей.");

        var vault = new VaultDocument
        {
            SchemaVersion = 2,
            VaultId = Clean(root, "vaultId", 100, Guid.NewGuid().ToString("N")),
            Name = Clean(root, "name", 48, "Мои пароли"),
            CreatedAt = ReadDate(root, "createdAt"),
            UpdatedAt = ReadDate(root, "updatedAt"),
        };

        try
        {
            foreach (JsonElement item in entries.EnumerateArray())
            {
                string password = Clean(item, "password", 1000, string.Empty);
                string title = Clean(item, "title", 80, string.Empty);
                string username = Clean(item, "username", 180, string.Empty);
                string phone = Clean(item, "phone", 60, string.Empty);
                string authProvider = LoginProvider.Normalize(Clean(item, "authProvider", 24, LoginProvider.Password));
                bool passwordSignIn = authProvider == LoginProvider.Password;
                if (title.Length == 0 || (username.Length == 0 && phone.Length == 0) || (passwordSignIn && password.Length == 0 && phone.Length == 0)) continue;
                var entry = new VaultEntry
                {
                    Id = Clean(item, "id", 100, Guid.NewGuid().ToString("N")),
                    Title = title,
                    Url = Clean(item, "url", 600, string.Empty),
                    Username = username,
                    AuthProvider = authProvider,
                    Phone = phone,
                    Favorite = ReadBool(item, "favorite"),
                    Strength = passwordSignIn && password.Length > 0 && item.TryGetProperty("strength", out JsonElement strength) && strength.TryGetInt32(out int score)
                        ? Math.Clamp(score, 0, 4)
                        : passwordSignIn && password.Length > 0 ? PasswordPolicy.Score(password) : 0,
                    CreatedAt = ReadDate(item, "createdAt"),
                    UpdatedAt = ReadDate(item, "updatedAt"),
                    Password = ProtectedSecret.FromString(password),
                };
                password = string.Empty;
                vault.Entries.Add(entry);
            }
            return vault;
        }
        catch
        {
            vault.Dispose();
            throw;
        }
    }

    private static string Clean(JsonElement element, string property, int max, string fallback)
    {
        if (!element.TryGetProperty(property, out JsonElement value) || value.ValueKind != JsonValueKind.String) return fallback;
        string text = value.GetString() ?? fallback;
        return text.Length <= max ? text : text[..max];
    }

    private static bool ReadBool(JsonElement element, string property) =>
        element.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.True;

    private static DateTimeOffset ReadDate(JsonElement element, string property) =>
        element.TryGetProperty(property, out JsonElement value) && value.TryGetDateTimeOffset(out DateTimeOffset date) ? date : DateTimeOffset.UtcNow;
}

public static class PasswordPolicy
{
    public static int Score(System.Security.SecureString password)
    {
        byte[] bytes = SecureStringUtil.ToUtf8(password);
        try
        {
            string temporary = System.Text.Encoding.UTF8.GetString(bytes);
            return Score(temporary);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static int Score(string password)
    {
        if (string.IsNullOrEmpty(password)) return 0;
        int score = password.Length >= 10 ? 1 : 0;
        if (password.Length >= 14) score++;
        int classes = 0;
        if (password.Any(char.IsLower)) classes++;
        if (password.Any(char.IsUpper)) classes++;
        if (password.Any(char.IsDigit)) classes++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) classes++;
        if (classes >= 3) score++;
        if (classes == 4 && password.Length >= 16) score++;
        string lower = password.ToLowerInvariant();
        if (lower.Contains("password") || lower.Contains("qwerty") || lower.Contains("пароль") || lower.Contains("12345")) score = Math.Min(score, 1);
        return Math.Clamp(score, 0, 4);
    }
}
