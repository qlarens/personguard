using System.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace PersonGuard.Desktop.Security;

public static class Argon2Kdf
{
    public const int VaultMemoryKiB = 131_072;
    public const int VaultIterations = 4;
    public const int VaultParallelism = 2;
    public const int AppMemoryKiB = 32_768;
    public const int AppIterations = 3;
    public const int AppParallelism = 1;

    public static byte[] Derive(SecureString password, byte[] salt, int memoryKiB, int iterations, int parallelism, int outputLength = 32)
    {
        byte[] passwordBytes = SecureStringUtil.ToUtf8(password);
        byte[] output = new byte[outputLength];
        try
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithSalt(salt)
                .WithMemoryAsKB(memoryKiB)
                .WithIterations(iterations)
                .WithParallelism(parallelism)
                .Build();
            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);
            generator.GenerateBytes(passwordBytes, output);
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}
