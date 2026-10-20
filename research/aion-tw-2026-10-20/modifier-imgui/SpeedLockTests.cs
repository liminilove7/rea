using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal static class SpeedLockTests
{
    private sealed class CountingMemory(IMemory inner) : IMemory
    {
        internal int Writes, FailAt;
        public byte[] Read(ulong a, int count) => inner.Read(a, count);
        public void Write(ulong a, byte[] value)
        {
            if (++Writes == FailAt) throw new IOException("fixture write failure");
            inner.Write(a, value);
        }
        public void Dispose() { }
    }
    private sealed class FakeTrial : ITrial
    {
        public double Seconds { get; set; }
        public string LogPath => "fixture";
        internal int Stops, Disposals, Polls;
        internal bool FailPoll, FailStop;
        public void Poll() { Polls++; if (FailPoll) throw new IOException("fixture identity failed"); }
        public string[] Stop(string reason) { Stops++; if (FailStop) throw new IOException("restore failed"); return []; }
        public void Dispose() => Disposals++;
    }
    internal static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool ok, string name) { if (!ok) throw new Exception(name); checks.Add(name); }
        bool Reject(Action action) { try { action(); return false; } catch (Exception e) when (MovementReader.Expected(e)) { return true; } }
        IntPtr allocation = Marshal.AllocHGlobal(4096);
        try
        {
            ulong c = (ulong)allocation.ToInt64(), b = c + 3000 - Profile.Interval;
            using var own = Process.GetCurrentProcess();
            using var native = new NativeMemory(own.Id, own.MainModule.FileName, own.StartTime.ToUniversalTime().ToFileTimeUtc(), true);
            var memory = new CountingMemory(native);
            bool identity = true;
            Action validate = () => { if (!identity) throw new InvalidOperationException("role changed"); };
            Action<string, object> audit = (_, _) => { };
            void Reset(SpeedField[] fields)
            {
                foreach (var f in fields) native.Write(f.Address, f.Width == 2 ? BitConverter.GetBytes((ushort)f.Baseline) : BitConverter.GetBytes(f.Baseline));
                memory.Writes = 0; memory.FailAt = 0;
            }
            bool Original(SpeedField[] fields) => fields.All(f => Mem.Value(native, f.Address, f.Width) == f.Baseline);
            var attack = SpeedSettings.Fields(SpeedKind.Attack, b, c, 400, 1200);
            Reset(attack); native.Write(attack[0].Address + 2, [0xA5, 0x5A]);
            native.Write(c + Profile.U, BitConverter.GetBytes((ushort)1200));
            var tx = new SpeedMutation(memory, attack, validate, audit); tx.Apply();
            Check(attack.All(f => Mem.Value(native, f.Address, f.Width) == 400) && native.Read(attack[0].Address + 2, 2).SequenceEqual(new byte[] { 0xA5, 0x5A }) && Mem.U16(native, c + Profile.U) == 1200,
                "Attack 400 uses exact u16/u32/u16 widths, preserves adjacent bytes and U");
            int writes = memory.Writes; tx.Poll(true);
            Check(memory.Writes == writes, "Unchanged locked tuple causes no repeated writes");
            native.Write(attack[1].Address, BitConverter.GetBytes(1092u)); tx.Poll(true);
            Check(memory.Writes == writes + 1 && Mem.Value(native, attack[1].Address, 4) == 400, "Checkbox maintenance reapplies only the externally changed field");
            Check(tx.Restore().Length == 0 && Original(attack), "Uncheck restores captured baseline after repeated maintenance");
            Check(Reject(tx.Apply), "Transaction cannot restart");
            foreach (float speed in SpeedSettings.MovementPresets)
            {
                var move = SpeedSettings.Fields(SpeedKind.Movement, b, c, speed); Reset(move);
                tx = new(memory, move, validate, audit); tx.Apply();
                Check(move.All(f => Mem.Value(native, f.Address, f.Width) == f.Desired) && tx.Restore().Length == 0 && Original(move),
                    $"Movement {speed:R}: exact speed/square/inverse/mirror apply and restore");
            }
            Reset(attack); memory.FailAt = 2; tx = new(memory, attack, validate, audit);
            Check(Reject(tx.Apply) && tx.Restore().Length == 0 && Original(attack), "Partial initial write failure restores all attempted fields");
            Reset(attack); tx = new(memory, attack, validate, audit); tx.Apply();
            native.Write(attack[0].Address, BitConverter.GetBytes((ushort)900)); writes = memory.Writes;
            Check(Reject(() => tx.Poll(false)) && memory.Writes == writes, "Timed trial detects an external change without freezing it");
            Check(tx.Restore().Length == 1 && Mem.U16(native, attack[0].Address) == 900 && Mem.U16(native, attack[2].Address) == 1200,
                "Final restoration preserves unknown external values and recovers owned values");
            Reset(attack); tx = new(memory, attack, validate, audit); tx.Apply(); identity = false; writes = memory.Writes;
            Check(Reject(() => tx.Poll(true)) && tx.Restore().Length == 3 && memory.Writes == writes, "Changed identity stops maintenance and prevents every stale-address restoration write");
            identity = true; tx.Restore(); Reset(attack);
            native.Write(attack[1].Address, BitConverter.GetBytes(1092u)); tx = new(memory, attack, validate, audit);
            Check(Reject(tx.Apply) && memory.Writes == 0, "Existing buff baseline rejects all writes");
            Reset(attack); bool disk = true;
            tx = new(memory, attack, validate, (_, _) => { if (!disk) throw new IOException("disk failed"); }); tx.Apply(); disk = false;
            Check(tx.Restore().Length > 0 && Original(attack), "Audit failure remains visible while restoration still runs");
            Check(Reject(() => SpeedSettings.Validate(SpeedKind.Attack, 399)) && Reject(() => SpeedSettings.Validate(SpeedKind.Attack, 700.5f)) &&
                Reject(() => SpeedSettings.Validate(SpeedKind.Movement, float.NaN)) && Reject(() => SpeedSettings.Validate(SpeedKind.Movement, float.PositiveInfinity)),
                "Invalid, noninteger, nonfinite settings rejected before session creation");
        }
        finally { Marshal.FreeHGlobal(allocation); }
        var logs = new List<string>(); var attackFake = new FakeTrial(); var movementFake = new FakeTrial(); int starts = 0;
        using (var locks = new SpeedLocks(logs.Add, (_, kind, _, _, _) => { starts++; return kind == SpeedKind.Attack ? attackFake : movementFake; }))
        {
            Check(!locks.Any && starts == 0, "Draft settings and initial unchecked state never start a session");
            Check(Reject(() => locks.Start(0, SpeedKind.Attack, 700, true)) && starts == 0, "Missing PID never reaches native factory");
            locks.Start(1, SpeedKind.Attack, 500, true);
            Check(Reject(() => locks.Start(2, SpeedKind.Movement, 9, true)) && starts == 1, "Concurrent modes cannot target different processes");
            locks.Start(1, SpeedKind.Movement, 9, true); attackFake.Seconds = movementFake.Seconds = 120; locks.Tick();
            Check(locks.Locked(SpeedKind.Attack) && locks.Locked(SpeedKind.Movement) && attackFake.Polls == 1 && movementFake.Polls == 1, "Independent checked modes both poll beyond 60 seconds");
            locks.Stop(SpeedKind.Attack, "uncheck");
            Check(!locks.Active(SpeedKind.Attack) && locks.Active(SpeedKind.Movement) && attackFake.Stops == 1 && attackFake.Disposals == 1, "Unchecking attack leaves movement running and releases its own resources once");
        }
        Check(movementFake.Stops == 1 && movementFake.Disposals == 1, "Window disposal stops remaining checked mode");
        attackFake = new(); movementFake = new();
        using (var locks = new SpeedLocks(logs.Add, (_, kind, _, _, _) => kind == SpeedKind.Attack ? attackFake : movementFake))
        {
            locks.Start(1, SpeedKind.Attack, 700, false); locks.Start(1, SpeedKind.Movement, 7.8f, true);
            attackFake.Seconds = 60; locks.Tick();
            Check(!locks.Active(SpeedKind.Attack) && locks.Active(SpeedKind.Movement), "Timed mode expires without cancelling a separate checked mode");
            movementFake.FailPoll = movementFake.FailStop = true; locks.Tick();
            Check(!locks.Any && movementFake.Disposals == 1 && logs.Any(l => l.Contains("未解决项")), "Poll and restore failures uncheck mode, release resources, retain visible failure");
        }
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks,
            scope = "Self-process allocated native memory and lifecycle fixtures. No game connection, no server effect claim." }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
