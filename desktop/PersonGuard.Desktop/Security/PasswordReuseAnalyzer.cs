using System.Security.Cryptography;
using PersonGuard.Desktop.Models;

namespace PersonGuard.Desktop.Security;

public static class PasswordReuseAnalyzer
{
    private static readonly byte[] FingerprintKey = RandomNumberGenerator.GetBytes(32);

    public static IReadOnlyList<PasswordReuseAlert> Analyze(IEnumerable<VaultEntry> entries)
    {
        List<VaultEntry> entryList = entries.ToList();
        var buckets = new Dictionary<string, List<VaultEntry>>(StringComparer.Ordinal);
        using var hmac = new HMACSHA256(FingerprintKey);

        foreach (VaultEntry entry in entryList)
        {
            if (!entry.UsesPassword) continue;

            byte[] plaintext = entry.Password.RevealUtf8();
            byte[] fingerprint = [];
            try
            {
                if (plaintext.Length == 0) continue;
                fingerprint = hmac.ComputeHash(plaintext);
                string key = Convert.ToHexString(fingerprint);
                if (!buckets.TryGetValue(key, out List<VaultEntry>? bucket))
                    buckets[key] = bucket = [];
                bucket.Add(entry);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(fingerprint);
            }
        }

        List<PasswordReuseAlert> alerts = buckets.Values
            .Where(bucket => bucket.Count > 1)
            .Select(bucket => new PasswordReuseAlert(bucket))
            .OrderByDescending(alert => alert.Entries.Count)
            .ThenBy(alert => alert.Entries[0].Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        var repeatedStatuses = new Dictionary<VaultEntry, (int Count, string Warning)>();
        foreach (PasswordReuseAlert alert in alerts)
        {
            foreach (VaultEntry entry in alert.Entries)
            {
                string others = string.Join(", ", alert.Entries
                    .Where(candidate => !ReferenceEquals(candidate, entry))
                    .Select(candidate => candidate.Title));
                repeatedStatuses[entry] = (alert.Entries.Count, $"Этот пароль используется в {alert.Entries.Count} записях. Совпадения: {others}. Смените его на уникальный.");
            }
        }

        foreach (VaultEntry entry in entryList)
        {
            if (repeatedStatuses.TryGetValue(entry, out var status))
                entry.SetPasswordReuseStatus(status.Count, status.Warning);
            else
                entry.SetPasswordReuseStatus(entry.UsesPassword ? 1 : 0, string.Empty);
        }

        return alerts;
    }
}
