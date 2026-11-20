using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace PersonGuard.Desktop.Presentation;

/// <summary>Short entrance and pointer transitions. Hiding content is always immediate.</summary>
public static class Motion
{
    public static readonly DependencyProperty EntranceProperty = DependencyProperty.RegisterAttached(
        "Entrance", typeof(bool), typeof(Motion), new PropertyMetadata(false, EntranceChanged));
    public static readonly DependencyProperty HoverProperty = DependencyProperty.RegisterAttached(
        "Hover", typeof(bool), typeof(Motion), new PropertyMetadata(false, HoverChanged));

    public static bool GetEntrance(DependencyObject target) => (bool)target.GetValue(EntranceProperty);
    public static void SetEntrance(DependencyObject target, bool value) => target.SetValue(EntranceProperty, value);
    public static bool GetHover(DependencyObject target) => (bool)target.GetValue(HoverProperty);
    public static void SetHover(DependencyObject target, bool value) => target.SetValue(HoverProperty, value);

    private static bool CanAnimate => SystemParameters.ClientAreaAnimation && !SystemParameters.HighContrast;

    private static void EntranceChanged(DependencyObject target, DependencyPropertyChangedEventArgs args)
    {
        if (target is not FrameworkElement element) return;
        if ((bool)args.NewValue)
        {
            element.Loaded += Enter;
            element.IsVisibleChanged += VisibilityChanged;
            element.Unloaded += Reset;
        }
        else
        {
            element.Loaded -= Enter;
            element.IsVisibleChanged -= VisibilityChanged;
            element.Unloaded -= Reset;
            Reset(element, new RoutedEventArgs());
        }
    }

    private static void Enter(object sender, RoutedEventArgs args)
    {
        var element = (FrameworkElement)sender;
        if (!element.IsVisible || !CanAnimate) return;
        // No secret or security state is retained in an animation callback.
        element.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(.35, 1, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }, FillBehavior = FillBehavior.Stop,
        });
    }

    private static void VisibilityChanged(object sender, DependencyPropertyChangedEventArgs args)
    {
        if ((bool)args.NewValue) Enter(sender, new RoutedEventArgs());
        else Reset(sender, new RoutedEventArgs());
    }

    private static void Reset(object sender, RoutedEventArgs args)
    {
        var element = (FrameworkElement)sender;
        if (element.HasAnimatedProperties) element.BeginAnimation(UIElement.OpacityProperty, null);
        if (element.RenderTransform is TranslateTransform translate && translate.HasAnimatedProperties)
            translate.BeginAnimation(TranslateTransform.YProperty, null);
    }

    private static void HoverChanged(DependencyObject target, DependencyPropertyChangedEventArgs args)
    {
        if (target is not FrameworkElement element) return;
        if ((bool)args.NewValue)
        {
            element.RenderTransform = new TranslateTransform();
            element.MouseEnter += PointerChanged;
            element.MouseLeave += PointerChanged;
            element.IsVisibleChanged += HoverVisibilityChanged;
            element.Unloaded += Reset;
        }
        else
        {
            element.MouseEnter -= PointerChanged;
            element.MouseLeave -= PointerChanged;
            element.IsVisibleChanged -= HoverVisibilityChanged;
            element.Unloaded -= Reset;
            Reset(element, new RoutedEventArgs());
        }
    }

    private static void HoverVisibilityChanged(object sender, DependencyPropertyChangedEventArgs args)
    {
        if (!(bool)args.NewValue) Reset(sender, new RoutedEventArgs());
    }

    private static void PointerChanged(object sender, MouseEventArgs args)
    {
        var element = (FrameworkElement)sender;
        if (element.RenderTransform is not TranslateTransform translate) return;
        if (!CanAnimate) { translate.BeginAnimation(TranslateTransform.YProperty, null); return; }
        translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(
            element.IsMouseOver ? -2 : 0, TimeSpan.FromMilliseconds(150))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        });
    }
}
