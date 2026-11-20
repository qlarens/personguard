using System.Windows.Media;

namespace PersonGuard.Desktop.Presentation;

public static class AppTypography
{
    // Static faces are embedded; no system font installation or network request is needed.
    public static FontFamily Family { get; } = new(
        new Uri("pack://application:,,,/PersonGuard;component/"), "./Assets/Fonts/Manrope/#Manrope");
}
