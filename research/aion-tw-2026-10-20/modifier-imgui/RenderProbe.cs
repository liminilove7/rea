using System.Numerics;
using System.Runtime.InteropServices;
using System.Text.Json;
using ImGuiNET;
using Veldrid;

namespace AionLab;

// Explicit offline verification: synthetic input enters the real renderer; no OS input.
internal sealed class RenderProbe
{
    private readonly string directory;
    private readonly List<string> checks = [];
    private int frame;
    internal RenderProbe(string directory)
    {
        this.directory = directory;
        Directory.CreateDirectory(directory);
    }
    private sealed class Snapshot(Vector2 point, bool down) : InputSnapshot
    {
        public IReadOnlyList<KeyEvent> KeyEvents => Array.Empty<KeyEvent>();
        public IReadOnlyList<MouseEvent> MouseEvents => [new MouseEvent(MouseButton.Left, down)];
        public IReadOnlyList<char> KeyCharPresses => Array.Empty<char>();
        public bool IsMouseDown(MouseButton button) => button == MouseButton.Left && down;
        public Vector2 MousePosition => point;
        public float WheelDelta => 0;
    }
    internal InputSnapshot Input(LabView ui)
    {
        int page = frame / 5;
        return new Snapshot(ui.NavigationCenters[page], frame % 5 == 1);
    }
    internal unsafe bool AfterDraw(GraphicsDevice device, Texture rendered, LabView ui, LabController controller)
    {
        if (frame % 5 == 4)
        {
            int page = frame / 5;
            if (ui.SelectedPage != page || controller.Active || ImGui.GetDrawData().TotalVtxCount == 0)
                throw new InvalidOperationException("Rendered navigation or offline-session invariant failed.");
            foreach (char glyph in "攻速实验移动怪物识别证据未连接还原")
                if (ImGui.GetIO().Fonts.Fonts[0].FindGlyphNoFallback(glyph).NativePtr == null)
                    throw new InvalidOperationException("Missing Chinese glyph: " + glyph);
            SaveFramebuffer(device, rendered, Path.Combine(directory, $"page-{page}.bmp"));
            checks.Add($"Page {page}: synthetic mouse selects actual ImGui navigation; GPU draw data nonempty; Chinese glyphs present; no trial active");
        }
        if (++frame < 20) return false;
        File.WriteAllText(Path.Combine(directory, "render-verification.json"),
            JsonSerializer.Serialize(new { allPassed = true, checks,
                method = "D3D11 offscreen framebuffer readback with the production ImGui renderer and synthetic Veldrid input; not OS mouse automation",
                limitations = "No game connection, no live modifications, no multi-DPI assertion" },
                new JsonSerializerOptions { WriteIndented = true }));
        return true;
    }
    private static void SaveFramebuffer(GraphicsDevice device, Texture source, string file)
    {
        if (source.Format != PixelFormat.B8_G8_R8_A8_UNorm && source.Format != PixelFormat.R8_G8_B8_A8_UNorm)
            throw new NotSupportedException("Unexpected framebuffer format: " + source.Format);
        using var staging = device.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
            source.Width, source.Height, 1, 1, source.Format, TextureUsage.Staging));
        device.WaitForIdle();
        using var copy = device.ResourceFactory.CreateCommandList();
        copy.Begin(); copy.CopyTexture(source, staging); copy.End();
        device.SubmitCommands(copy); device.WaitForIdle();
        var mapped = device.Map(staging, MapMode.Read);
        try
        {
            // Top-down 32-bit BMP. Read only our own swapchain, not the desktop.
            int width = checked((int)source.Width), height = checked((int)source.Height);
            using var writer = new BinaryWriter(File.Create(file));
            writer.Write((ushort)0x4D42); writer.Write(54 + width * height * 4);
            writer.Write(0); writer.Write(54); writer.Write(40);
            writer.Write(width); writer.Write(-height); writer.Write((ushort)1); writer.Write((ushort)32);
            writer.Write(0); writer.Write(width * height * 4);
            writer.Write(2835); writer.Write(2835); writer.Write(0); writer.Write(0);
            byte[] row = new byte[width * 4];
            var colors = new HashSet<int>();
            for (int y = 0; y < height; y++)
            {
                Marshal.Copy(IntPtr.Add(mapped.Data, checked(y * (int)mapped.RowPitch)), row, 0, row.Length);
                if (source.Format == PixelFormat.R8_G8_B8_A8_UNorm)
                    for (int x = 0; x < row.Length; x += 4) (row[x], row[x + 2]) = (row[x + 2], row[x]);
                if (colors.Count < 128)
                    for (int x = 0; x < row.Length; x += 4) colors.Add(row[x] | (row[x + 1] << 8) | (row[x + 2] << 16));
                writer.Write(row);
            }
            if (colors.Count < 16) throw new InvalidOperationException("Framebuffer is blank or unexpectedly uniform.");
        }
        finally { device.Unmap(staging); }
    }
}
