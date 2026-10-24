using System.Runtime.InteropServices;
using System.Text.Json;

namespace AionLab;

internal static class SelectedTargetAttackTests
{
    private sealed class Fixture : ISelectedAttackSession
    {
        internal bool Foreground = true, Stop, Fail, FailDispose;
        internal int Sends, Disposals, Holds, Releases;
        internal ushort LastKey, MovementKey;
        public bool IsForeground() => Foreground;
        public bool StopRequested() => Stop;
        public void SendAttackOnce(ushort key) { Sends++; LastKey = key; if (Fail) throw new IOException("partial input/audit failure"); }
        public void HoldMovement(ushort key) { Holds++; MovementKey = key; }
        public void ReleaseMovement() { Releases++; MovementKey = 0; }
        public void Dispose() { Disposals++; if (FailDispose) throw new IOException("key release failed"); MovementKey = 0; }
    }
    internal static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool ok, string name) { if (!ok) throw new Exception(name); checks.Add(name); }
        double now = 0; var fixture = new Fixture(); int starts = 0;
        var logs = new List<string>();
        using (var c = new SelectedAttackController(logs.Add, (_, key, interval, _) => { starts++; Check(key == 0x31 && interval == 2.5, "Factory receives actual requested key and repeat interval"); return fixture; }, () => now))
        {
            c.Tick(); Check(starts == 0 && !c.Active, "Initial state never connects or emits input");
            bool bad = false; try { c.Arm(1, 0x77); } catch (ArgumentException) { bad = true; }
            Check(bad && starts == 0, "F8 stop key cannot also be an attack key");
            c.Arm(1, 0x31); now = 4.9; c.Tick(); Check(fixture.Sends == 0 && c.Preparing, "Preparation emits no input");
            now = 5; c.Tick(); Check(fixture.Sends == 1 && fixture.LastKey == 0x31 && c.State == AttackInputState.Running, "First foreground tick sends configured top-row 1 once");
            c.Tick(); now = 7.49; c.Tick(); Check(fixture.Sends == 1, "Render ticks do not flood repeats");
            now = 9; c.Tick(); now = 9.1; c.Tick(); Check(fixture.Sends == 2, "Late tick sends one request without catch-up bursts");
            now = 35; c.Tick(); c.Tick(); Check(!c.Active && c.State == AttackInputState.Completed && fixture.Sends == 2 && fixture.Disposals == 1, "Thirty-second expiry stops and releases exactly once");
        }
        fixture = new() { Foreground = false }; now = 0;
        using (var c = new SelectedAttackController(logs.Add, (_, _, _, _) => fixture, () => now))
        {
            c.Arm(1, 0x31); now = 5; c.Tick(); Check(fixture.Sends == 0 && !c.Active && fixture.Disposals == 1, "No foreground game at deadline cancels without key input");
        }
        fixture = new(); now = 0;
        using (var c = new SelectedAttackController(logs.Add, (_, _, _, _) => fixture, () => now))
        {
            c.Arm(1, 0x31, 2.5, new(0x41, 0x44, 1)); now = 5; c.Tick();
            Check(fixture.Holds == 1 && fixture.MovementKey == 0x41 && fixture.Sends == 1, "First phase holds A while issuing the attack key");
            now = 6; c.Tick(); Check(fixture.Holds == 2 && fixture.MovementKey == 0x44 && fixture.Sends == 1, "Next phase releases A before holding D without extra attacks");
            fixture.Foreground = false; now = 6.1; c.Tick();
            Check(fixture.Sends == 1 && !c.Active && fixture.Disposals == 1 && fixture.MovementKey == 0, "Focus loss between attack ticks stops loop and releases movement");
        }
        fixture = new() { Stop = true }; now = 0;
        using (var c = new SelectedAttackController(logs.Add, (_, _, _, _) => fixture, () => now))
        {
            c.Arm(1, 0x31); c.Tick(); Check(fixture.Sends == 0 && !c.Active, "Emergency-stop signal works during preparation");
        }
        fixture = new() { Fail = true }; now = 0;
        using (var c = new SelectedAttackController(logs.Add, (_, _, _, _) => fixture, () => now))
        {
            c.Arm(1, 0x31, 2.5, new(0x41, 0x44, 1)); now = 5; c.Tick(); now = 10; c.Tick();
            Check(c.State == AttackInputState.Failed && fixture.Sends == 1 && fixture.Disposals == 1 && fixture.MovementKey == 0, "Partial input/audit failure releases movement and never retries attacks");
        }
        fixture = new(); now = 0;
        var closing = new SelectedAttackController(logs.Add, (_, _, _, _) => fixture, () => now);
        closing.Arm(1, 0x31); closing.Dispose(); Check(fixture.Sends == 0 && fixture.Disposals == 1, "Window closure cancels preparation without input");
        fixture = new() { FailDispose = true }; now = 0;
        using (var c = new SelectedAttackController(logs.Add, (_, _, _, _) => fixture, () => now))
        {
            c.Arm(1, 0x31); c.Cancel("fixture");
            bool bad = false; try { c.Arm(1, 0x31); } catch (InvalidOperationException) { bad = true; }
            Check(c.CleanupPending && bad, "Failed cleanup retains session ownership and refuses a new run");
            fixture.FailDispose = false; c.RetryCleanup(); Check(!c.CleanupPending && fixture.Disposals == 2, "Explicit retry resolves retained key-release session");
        }
        Check(Marshal.SizeOf<ForegroundAttackSession.KeyboardInputPacket>() == 40 && Marshal.OffsetOf<ForegroundAttackSession.KeyboardInputPacket>("Data").ToInt32() == 8,
            "Native x64 INPUT packet matches 40-byte aligned representation");
        var packets = ForegroundAttackSession.BuildInputs(2);
        Check(packets.Length == 2 && packets.All(p => p.Type == 1 && p.Data.Keyboard.Scan == 2) && packets[0].Data.Keyboard.Flags == 8 && packets[1].Data.Keyboard.Flags == 10,
            "Attack uses paired scan-code down/up events");
        var sentFlags = new List<uint>(); uint accepted = 1;
        var emitter = new OwnedKeyEmitter(xs => { sentFlags.AddRange(xs.Select(x => x.Data.Keyboard.Flags)); return new(accepted, 0); }, (_, _) => { });
        emitter.Hold(0x1E); Check(emitter.HeldCount == 1, "Direction down retains ownership until key up is accepted");
        accepted = 0; bool rejected = false; try { emitter.ReleaseAll(); } catch (IOException) { rejected = true; }
        Check(rejected && emitter.HeldCount == 1 && sentFlags.Last() == 10, "Rejected key up retains ownership and never emits another down");
        accepted = 1; emitter.ReleaseAll(); Check(emitter.HeldCount == 0 && sentFlags.Last() == 10, "Retry releases only the outstanding scan code");
        emitter = new OwnedKeyEmitter(_ => new(1, 0), (_, _) => { }); rejected = false;
        try { emitter.Press(2); } catch (IOException) { rejected = true; }
        emitter.ReleaseAll(); Check(rejected && emitter.HeldCount == 0, "Partial attack down is released during cleanup without another attack");
        bool diskFailed = false;
        emitter = new OwnedKeyEmitter(xs => new((uint)xs.Length, 0), (_, _) => { if (diskFailed) throw new IOException("audit disk failure"); });
        emitter.Hold(0x1E); diskFailed = true; rejected = false;
        try { emitter.ReleaseAll(); } catch (IOException) { rejected = true; }
        Check(rejected && emitter.HeldCount == 0, "Audit failure cannot prevent an owned movement key from being released");
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks,
            scope = "Injected input sessions/clock and native struct layout only. No OS keyboard events, game connection, target/death/distance sensing or navigation." }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
