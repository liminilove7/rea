using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal static class AttackBaselineTests
{
    private sealed class ProbeMemory(IMemory inner) : IMemory
    {
        internal int Writes;
        internal ulong FailRead;
        public byte[] Read(ulong address, int count) => address == FailRead ? throw new IOException("fixture read failure") : inner.Read(address, count);
        public void Write(ulong address, byte[] bytes) { Writes++; inner.Write(address, bytes); }
        public void Dispose() { }
    }
    internal static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool ok, string label) { if (!ok) throw new Exception(label); checks.Add(label); }
        bool Reject(Action action) { try { action(); return false; } catch (Exception e) when (MovementReader.Expected(e)) { return true; } }
        Check(AttackRules.IntervalForPercent(1200, 25) == 900 && AttackRules.IntervalForPercent(2400, 25) == 1800,
            "Same 25 percent interval reduction respects different 1200 and 2400 weapon baselines");
        Check(AttackRules.IntervalForPercent(2400, 9) == 2184 && AttackRules.IntervalForPercent(1200, 9) == 1092,
            "Nine percent arithmetic matches 1200 control and scales to 2400; not a server-rate assertion");
        Check(AttackRules.IntervalForPercent(65535, 0) == 65535 && AttackRules.IntervalForPercent(1201, 50) == 601 && AttackRules.IntervalForPercent(400, 65) == 400,
            "Exact integer bounds, declared midpoint rounding, and visible tool lower bound");
        Check(Reject(() => AttackRules.IntervalForPercent(0, 25)) && Reject(() => AttackRules.IntervalForPercent(2400, 66)) &&
            Reject(() => SpeedSettings.Fields(SpeedKind.Attack, 0, 0, 1800)) && Reject(() => SpeedSettings.Fields(SpeedKind.Attack, 0, 0, 2500, 2400)),
            "Missing baselines and slower-than-baseline targets rejected before writes");
        IntPtr allocation = Marshal.AllocHGlobal(4096);
        try
        {
            ulong c = (ulong)allocation.ToInt64(), b = c + 3000 - Profile.Interval;
            using var own = Process.GetCurrentProcess();
            using var native = new NativeMemory(own.Id, own.MainModule.FileName, own.StartTime.ToUniversalTime().ToFileTimeUtc(), true);
            var memory = new ProbeMemory(native);
            void Reset(uint baseline)
            {
                native.Write(b + Profile.Interval, BitConverter.GetBytes((ushort)baseline));
                native.Write(b + Profile.Mirror, BitConverter.GetBytes(baseline));
                native.Write(c + Profile.U, BitConverter.GetBytes((ushort)baseline));
                native.Write(c + Profile.V, BitConverter.GetBytes((ushort)baseline));
                native.Write(c + Profile.Scale, BitConverter.GetBytes(1f)); memory.Writes = 0;
            }
            Action<string, object> audit = (_, _) => { };
            foreach (uint baseline in new uint[] { 1200, 1500, 2400, 2800 })
            {
                Reset(baseline);
                var state = AttackRules.Read(memory, b, c);
                Check(state.Consistent && state.Interval == baseline && memory.Writes == 0, $"Baseline {baseline} captured read-only without a fixed 1200 assumption");
                int desired = AttackRules.IntervalForPercent(baseline, 25);
                var tx = new SpeedMutation(memory, SpeedSettings.Fields(SpeedKind.Attack, b, c, desired, baseline),
                    () => AttackRules.CheckContext(memory, c, baseline), audit);
                tx.Apply();
                Check(Mem.U16(native, b + Profile.Interval) == desired && Mem.Value(native, b + Profile.Mirror, 4) == desired &&
                    Mem.U16(native, c + Profile.V) == desired && Mem.U16(native, c + Profile.U) == baseline,
                    $"Baseline {baseline} applies relative target and preserves its own U");
                Check(tx.Restore().Length == 0 && AttackRules.Read(memory, b, c).Consistent && Mem.U16(native, b + Profile.Interval) == baseline,
                    $"Baseline {baseline} restores that exact weapon interval rather than hardcoded 1200");
            }
            Reset(2400);
            var target = new Target { Pid = 7, Birth = 8, Base = b };
            var role = new Role { Character = c };
            var binding = new AttackBinding(7, 8, b, c, 2400);
            var stable = AttackRules.Read(memory, b, c);
            AttackRules.CheckBinding(binding, target, role, stable);
            Check(memory.Writes == 0 && Reject(() => AttackRules.CheckBinding(binding with { Interval = 1200 }, target, role, stable)) &&
                Reject(() => AttackRules.CheckBinding(binding with { Birth = 9 }, target, role, stable)) &&
                Reject(() => AttackRules.CheckBinding(binding with { Character = c + 1 }, target, role, stable)),
                "Selection is bound to sampled baseline, process birth, and character, not stale UI values");
            var bow = new SpeedMutation(memory, SpeedSettings.Fields(SpeedKind.Attack, b, c, 1800, 2400),
                () => AttackRules.CheckContext(memory, c, 2400), audit); bow.Apply();
            Reset(1200); int writes = memory.Writes;
            Check(Reject(() => bow.Poll(true)) && bow.Restore().Length == 3 && memory.Writes == writes && Mem.U16(native, b + Profile.Interval) == 1200,
                "Switch from bow signature to 1200 stops maintenance and never restores old 2400 into new weapon");
            Reset(2400); bow = new(memory, SpeedSettings.Fields(SpeedKind.Attack, b, c, 1800, 2400), () => AttackRules.CheckContext(memory, c, 2400), audit);
            bow.Apply(); native.Write(c + Profile.Scale, BitConverter.GetBytes(1.1f)); writes = memory.Writes;
            Check(Reject(() => bow.Poll(true)) && bow.Restore().Length == 3 && memory.Writes == writes, "Animation coefficient change stops both maintenance and stale-context restoration writes");
            Reset(2400); native.Write(b + Profile.Mirror, BitConverter.GetBytes(2184u));
            var inconsistent = AttackRules.Read(memory, b, c);
            Check(!inconsistent.Consistent && Reject(() => AttackRules.CheckBinding(binding, target, role, inconsistent)) && memory.Writes == 0,
                "Mixed weapon/buff tuple cannot become a fresh consistent baseline");
            Reset(2400); memory.FailRead = c + Profile.V;
            var partial = AttackRules.Read(memory, b, c);
            Check(partial.Interval == 2400 && partial.U == 2400 && partial.V == null && partial.Errors.Length == 1 && !partial.Consistent,
                "Partial read failure preserves other observed fields and an explicit error");
            memory.FailRead = 0;
            Check(!stable.SameValues(inconsistent), "Two-read stabilization detects a changed tuple");
        }
        finally { Marshal.FreeHGlobal(allocation); }
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks,
            scope = "Own process native fixtures; current bow baseline only observed read-only. No weapon-ID resolver and no live game writes." },
            new JsonSerializerOptions { WriteIndented = true }));
    }
}
