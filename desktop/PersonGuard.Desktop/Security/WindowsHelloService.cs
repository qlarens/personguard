using System.Windows;
using System.Windows.Interop;
using Windows.Security.Credentials.UI;

namespace PersonGuard.Desktop.Security;

public static class WindowsHelloService
{
    public static async Task<bool> IsAvailableAsync()
    {
        try
        {
            UserConsentVerifierAvailability availability = await UserConsentVerifier.CheckAvailabilityAsync();
            return availability == UserConsentVerifierAvailability.Available;
        }
        catch { return false; }
    }

    public static async Task<bool> VerifyAsync(Window owner, string message)
    {
        try
        {
            nint hwnd = new WindowInteropHelper(owner).EnsureHandle();
            UserConsentVerificationResult result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(hwnd, message);
            return result == UserConsentVerificationResult.Verified;
        }
        catch { return false; }
    }
}

