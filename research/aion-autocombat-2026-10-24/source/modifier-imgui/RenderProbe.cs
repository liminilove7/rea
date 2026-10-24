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
    private readonly bool controls;
    private readonly List<FixtureTrial> trials = [];
    private int frame;
    internal RenderProbe(string directory, bool controls = false)
    {
        this.controls = controls;
        this.directory = directory;
        Directory.CreateDirectory(directory);
    }
    private sealed class FixtureTrial : ITrial
    {
        public double Seconds => 0;
        public string LogPath => "offline synthetic fixture";
        internal int Stops, Disposals;
        public void Poll() { }
        public string[] Stop(string reason) { Stops++; return []; }
        public void Dispose() => Disposals++;
    }
    internal ITrial BeginFixture(int pid, SpeedKind kind, float value, bool maintain, AttackBinding binding)
    {
        if (kind == SpeedKind.Attack)
        {
            if (binding?.Interval != 2400 || binding.Pid != pid || value != 1800 || !maintain)
                throw new InvalidOperationException("Actual UI did not bind the 2400 fixture with a 25-percent target of 1800.");
            checks.Add("Actual UI passes sampled 2400 binding and relative 1800 target to injected session factory");
        }
        var trial = new FixtureTrial(); trials.Add(trial); return trial;
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
        if (controls)
        {
            var point = frame switch
            {
                1 or 2 or 22 or 23 => ui.LockCenters[0],
                6 or 7 => ui.NavigationCenters[1],
                9 or 10 or 14 or 15 => ui.LockCenters[1],
                19 or 20 => ui.NavigationCenters[0],
                _ => new Vector2(10, 10)
            };
            return new Snapshot(point, frame is 1 or 6 or 9 or 14 or 19 or 22);
        }
        int page = frame / 5;
        return new Snapshot(ui.NavigationCenters[page], frame % 5 == 1);
    }
    internal unsafe bool AfterDraw(GraphicsDevice device, Texture rendered, LabView ui, LabController controller)
    {
        if (controls)
        {
            bool attack = ui.IsSpeedLocked(SpeedKind.Attack), movement = ui.IsSpeedLocked(SpeedKind.Movement);
            if (frame is 4 or 12 or 17 or 25)
            {
                bool expectedAttack = frame != 25, expectedMovement = frame == 12;
                if (attack != expectedAttack || movement != expectedMovement || controller.Active)
                    throw new InvalidOperationException($"Checkbox interaction failed frame {frame}: attack={attack}, movement={movement}");
                SaveFramebuffer(device, rendered, Path.Combine(directory, $"controls-{frame}.bmp"));
                checks.Add($"Frame {frame}: actual ImGui checkbox input => attack={attack}, movement={movement}");
            }
            if (++frame < 26) return false;
            if (trials.Count != 2 || trials.Any(t => t.Stops != 1 || t.Disposals != 1))
                throw new InvalidOperationException("Checkbox sessions did not release exactly once.");
            checks.Add("Both UI checkbox sessions restore and dispose exactly once; factory has no native/game access");
            File.WriteAllText(Path.Combine(directory, "render-verification.json"), JsonSerializer.Serialize(new { allPassed = true, checks,
                method = "Production ImGui + D3D11 framebuffer and synthetic input; injected fake sessions; game discovery/read/write disabled" },
                new JsonSerializerOptions { WriteIndented = true }));
            return true;
        }
        if (frame % 5 == 4)
        {
            int page = frame / 5;
            if (ui.SelectedPage != page || controller.Active || ui.HasActiveSpeedSession || ui.HasActiveCombatSession || ui.HasActiveHealthObservation || ImGui.GetDrawData().TotalVtxCount == 0)
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
