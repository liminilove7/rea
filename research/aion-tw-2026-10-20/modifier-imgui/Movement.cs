using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal static class MovementReader
{
    internal static bool Expected(Exception e) => e is Win32Exception or IOException or InvalidOperationException
        or ArgumentException or UnauthorizedAccessException;
    internal static readonly string[] Names = ["panel", "speed", "square", "inverse", "mirror"];
    internal static ulong[] Addresses(ulong b, ulong c) => [c + 0x38, c + 0x70C, c + 0x710, c + 0x714, b + 0x142DC14];
    internal static readonly string[] Relative = ["C+0x38", "C+0x70C", "C+0x710", "C+0x714", "B+0x142DC14"];
    internal static uint Bits(float value) => BitConverter.SingleToUInt32Bits(value);
    internal static uint[] Tuple(float speed) => [Bits(speed), Bits(speed), Bits(speed * speed), Bits(1f / speed), Bits(speed)];
    internal static MovementField[] ReadFields(IMemory memory, ulong b, ulong c)
    {
        var addresses = Addresses(b, c);
        var fields = new MovementField[5];
        for (int i = 0; i < fields.Length; i++)
        {
            try
            {
                var bytes = memory.Read(addresses[i], 4);
                float value = BitConverter.ToSingle(bytes);
                bool finite = float.IsFinite(value);
                fields[i] = new(Names[i], Relative[i], Mem.Hex(addresses[i]), finite ? value : null,
                    "0x" + BitConverter.ToUInt32(bytes).ToString("x8"), finite ? null : "非有限float32；保留原始位表示");
            }
            catch (Exception e) when (Expected(e))
            {
                fields[i] = new(Names[i], Relative[i], Mem.Hex(addresses[i]), null, null, e.Message);
            }
        }
        return fields;
    }
    internal static bool Consistent(MovementField[] fields)
    {
        if (fields.Length != 5 || fields.Any(f => !f.Value.HasValue)) return false;
        float speed = fields[1].Value.Value;
        if (speed < .0001f || !float.IsFinite(speed * speed)) return false;
        uint[] expected = Tuple(speed);
        return fields.Select((f, i) => Bits(f.Value.Value) == expected[i]).All(v => v);
    }
    internal static Observation<MovementSnapshot> Capture(int pid)
    {
        try
        {
            var target = Target.Capture(pid);
            using var memory = new NativeMemory(pid, target.Path, target.Birth, false);
            var role = Role.Resolve(memory, target.Base, target.Engine);
            var fields = ReadFields(memory, target.Base, role.Character);
            string reason = null;
            bool identity = false;
            try { target.Check(); identity = role.Same(Role.Resolve(memory, target.Base, target.Engine)); }
            catch (Exception e) when (Expected(e)) { reason = e.Message; }
            var snapshot = new MovementSnapshot(fields[1].Value, "客户端float标度；世界距离/时间单位未实测",
                new Evidence("REA既有RVA0x89ADB0字段布局；辅助Win32只读顺序采样", DateTimeOffset.UtcNow, Profile.GameHash))
            { Pid = pid, ModuleBase = Mem.Hex(target.Base), Character = Mem.Hex(role.Character), Fields = fields, IdentityReadbackMatched = identity };
            bool consistent = Consistent(fields);
            return new(identity && consistent ? Availability.Ready : Availability.Stale,
                reason ?? (!identity ? "角色身份在采样期间变化；保留已采字段但不认作当前快照。" :
                consistent ? "五字段位表示一致；非原子采样，不代表服务器位移频率。" : "存在未知或不一致字段；保留各字段与错误，不用于写入。"), snapshot);
        }
        catch (Exception e) when (Expected(e)) { return new(Availability.Unavailable, e.Message, null); }
    }
}

// Exactly five float32 fields; no code patch, remote call, continuous freeze, or movement packet.
internal sealed class MovementMutation(IMemory memory, ulong b, ulong c, float desired,
    Action validate, Action<string, object> audit)
{
    private readonly ulong[] addresses = MovementReader.Addresses(b, c);
    private readonly uint[] originals = new uint[5];
    private readonly bool[] attempted = new bool[5];
    private readonly uint[] values = MovementReader.Tuple(desired);
    private bool started;
    private uint Read(int i) => Mem.Value(memory, addresses[i], 4);
    internal void Apply()
    {
        if (started) throw new InvalidOperationException("同一移速事务不能重复应用。");
        if (!float.IsFinite(desired) || desired <= 6f || desired > 7.8f)
            throw new ArgumentOutOfRangeException(nameof(desired), "当前实验仅接受大于6、至7.8；不是服务器上限。");
        started = true;
        validate();
        uint[] baseline = MovementReader.Tuple(6f);
        for (int i = 0; i < 5; i++)
        {
            originals[i] = Read(i);
            if (originals[i] != baseline[i]) throw new InvalidOperationException("本次移速实验仅支持无增益6.0基线，所有缓存必须一致。");
        }
        audit("movement-baseline", new { originals, desired, maximumSeconds = 60 });
        for (int i = 0; i < 5; i++)
        {
            validate();
            if (Read(i) != originals[i]) throw new InvalidOperationException("写入前移速被外部更新。");
            audit("movement-apply-intent", new { field = MovementReader.Names[i], address = Mem.Hex(addresses[i]), beforeBits = originals[i], desiredBits = values[i] });
            attempted[i] = true;
            memory.Write(addresses[i], BitConverter.GetBytes(values[i]));
            uint actual = Read(i);
            audit("movement-apply-readback", new { field = MovementReader.Names[i], actualBits = actual });
            if (actual != values[i]) throw new InvalidOperationException("移速写入回读不符。");
        }
    }
    internal void Poll()
    {
        validate();
        uint[] actual = Enumerable.Range(0, 5).Select(Read).ToArray();
        bool changed = !actual.SequenceEqual(values);
        audit("movement-observed", new { actualBits = actual, desiredBits = values, changedExternally = changed });
        if (changed) throw new InvalidOperationException("移速元组已外部更新；停止且不重新锁定。");
    }
    internal string[] Restore()
    {
        var issues = new List<string>();
        for (int i = 4; i >= 0; i--)
        {
            if (!attempted[i]) continue;
            try
            {
                validate();
                uint current = Read(i);
                if (current == originals[i])
                {
                    attempted[i] = false;
                    try { audit("movement-restore-already-original", new { field = MovementReader.Names[i], address = Mem.Hex(addresses[i]), actualBits = current, memoryWritten = false }); }
                    catch (IOException e) { issues.Add("还原日志：" + e.Message); }
                    continue;
                }
                if (current != values[i])
                {
                    issues.Add(MovementReader.Names[i] + "外部值已保留");
                    try { audit("movement-restore-external-preserved", new { field = MovementReader.Names[i], actualBits = current, memoryWritten = false }); }
                    catch (IOException e) { issues.Add("还原日志：" + e.Message); }
                    continue;
                }
                try { audit("movement-restore-intent", new { field = MovementReader.Names[i], address = Mem.Hex(addresses[i]), beforeBits = current, originalBits = originals[i] }); }
                catch (IOException e) { issues.Add("还原日志：" + e.Message); }
                validate();
                if (Read(i) != values[i]) throw new InvalidOperationException("还原前移速再次变化。");
                memory.Write(addresses[i], BitConverter.GetBytes(originals[i]));
                if (Read(i) != originals[i]) throw new InvalidOperationException("移速还原回读失败。");
                attempted[i] = false;
                try { audit("movement-restore-readback", new { field = MovementReader.Names[i], actualBits = originals[i] }); }
                catch (IOException e) { issues.Add("还原日志：" + e.Message); }
            }
            catch (Exception e) when (MovementReader.Expected(e)) { issues.Add(MovementReader.Names[i] + "：" + e.Message); }
        }
        return issues.ToArray();
    }
}

internal sealed class MovementTrial : ITrial
{
    private readonly Target target;
    private readonly Role role;
    private readonly NativeMemory memory;
    private readonly Audit audit;
    private readonly MovementMutation mutation;
    private readonly Stopwatch clock = new();
    public double Seconds => clock.Elapsed.TotalSeconds;
    public string LogPath => audit.FileName;
    private MovementTrial(Target target, Role role, NativeMemory memory, Audit audit, float desired)
    {
        this.target = target; this.role = role; this.memory = memory; this.audit = audit;
        mutation = new(memory, target.Base, role.Character, desired, Validate, audit.Record);
    }
    private void Validate()
    {
        target.Check();
        if (!role.Same(Role.Resolve(memory, target.Base, target.Engine)))
            throw new InvalidOperationException("当前角色重建；不写历史移速地址。");
    }
    internal static MovementTrial Begin(int pid, float desired, string directory)
    {
        var target = Target.Capture(pid);
        NativeMemory memory = null; Audit audit = null; MovementTrial session = null;
        try
        {
            memory = new NativeMemory(pid, target.Path, target.Birth, true);
            var role = Role.Resolve(memory, target.Base, target.Engine);
            audit = new Audit(directory);
            session = new MovementTrial(target, role, memory, audit, desired);
            audit.Record("movement-session", new { pid, path = target.Path, birthUtc = DateTime.FromFileTimeUtc(target.Birth), gameSHA256 = Profile.GameHash,
                moduleBase = Mem.Hex(target.Base), character = Mem.Hex(role.Character), desired, maximumSeconds = 60,
                method = "Local five-field experiment; no server buff, notification call or physical-distance proof" });
            session.mutation.Apply(); session.clock.Start(); return session;
        }
        catch (Exception e)
        {
            string[] issues = [];
            try { if (session != null) issues = session.mutation.Restore(); }
            finally { memory?.Dispose(); audit?.Dispose(); }
            throw new InvalidOperationException(e.Message + (issues.Length == 0 ? "；已检查本次写入的还原。" : "；还原问题：" + string.Join("；", issues)), e);
        }
    }
    public void Poll()
    {
        try { mutation.Poll(); }
        catch (Exception e) when (MovementReader.Expected(e))
        {
            try { audit.Record("movement-poll-failure", new { elapsedSeconds = Seconds, reason = e.Message }); }
            catch (IOException) { /* Preserve the original failure; restoration still runs. */ }
            throw;
        }
    }
    public string[] Stop(string reason)
    {
        var issues = mutation.Restore().ToList();
        try { audit.Record("movement-completed", new { elapsedSeconds = Seconds, reason, issues }); }
        catch (IOException e) { issues.Add("完成日志：" + e.Message); }
        return issues.ToArray();
    }
    public void Dispose() { memory.Dispose(); audit.Dispose(); }
}

internal static class MovementTests
{
    private sealed class FixtureMemory(IMemory inner) : IMemory
    {
        internal int Writes, FailWrite;
        internal ulong FailRead;
        public byte[] Read(ulong address, int count) => address == FailRead ? throw new IOException("fixture read failure") : inner.Read(address, count);
        public void Write(ulong address, byte[] data) { Writes++; if (Writes == FailWrite) throw new IOException("fixture write failure"); inner.Write(address, data); }
        public void Dispose() { }
    }
    internal static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool ok, string name) { if (!ok) throw new Exception(name); checks.Add(name); }
        IntPtr allocation = Marshal.AllocHGlobal(4096);
        try
        {
            ulong c = (ulong)allocation.ToInt64(), b = c + 3000 - 0x142DC14;
            ulong[] addresses = MovementReader.Addresses(b, c);
            using var own = Process.GetCurrentProcess();
            using var memory = new NativeMemory(own.Id, own.MainModule.FileName, own.StartTime.ToUniversalTime().ToFileTimeUtc(), true);
            void Reset() { var baseline = MovementReader.Tuple(6f); for (int i = 0; i < 5; i++) memory.Write(addresses[i], BitConverter.GetBytes(baseline[i])); }
            Action valid = () => { }; Action<string, object> log = (_, _) => { };
            Reset();
            Check(MovementReader.Consistent(MovementReader.ReadFields(memory, b, c)), "Native fixture baseline six has consistent square/inverse/mirrors");
            var mutation = new MovementMutation(memory, b, c, 7.8f, valid, log); mutation.Apply(); mutation.Poll();
            Check(MovementReader.Consistent(MovementReader.ReadFields(memory, b, c)) && Mem.Value(memory, addresses[2], 4) == MovementReader.Bits(60.840004f), "Normal-scroll float32 tuple reproduced exactly in own native memory");
            Check(mutation.Restore().Length == 0 && Mem.Value(memory, addresses[0], 4) == MovementReader.Bits(6f), "Five fields restored/read back");
            memory.Write(addresses[4], BitConverter.GetBytes(7.8f)); var fault = new FixtureMemory(memory); mutation = new(fault, b, c, 7.8f, valid, log);
            bool rejected = false; try { mutation.Apply(); } catch (InvalidOperationException) { rejected = true; }
            Check(rejected && fault.Writes == 0, "Different existing buff refuses every write"); Reset();
            fault = new(memory) { FailWrite = 3 }; mutation = new(fault, b, c, 7.8f, valid, log);
            rejected = false; try { mutation.Apply(); } catch (IOException) { rejected = true; }
            Check(rejected && mutation.Restore().Length == 0 && MovementReader.Consistent(MovementReader.ReadFields(memory, b, c)), "Partial application failure restores fields already attempted");
            mutation = new(memory, b, c, 7.8f, valid, log); mutation.Apply(); memory.Write(addresses[0], BitConverter.GetBytes(7f));
            Check(mutation.Restore().Length == 1 && Mem.Value(memory, addresses[0], 4) == MovementReader.Bits(7f) && Mem.Value(memory, addresses[1], 4) == MovementReader.Bits(6f), "External field preserved while other owned fields restore"); Reset();
            bool identity = true; mutation = new(memory, b, c, 7.8f, () => { if (!identity) throw new InvalidOperationException("role replaced"); }, log);
            mutation.Apply(); identity = false;
            Check(mutation.Restore().Length == 5 && Mem.Value(memory, addresses[0], 4) == MovementReader.Bits(7.8f), "Changed identity prevents restoration writes to old role"); identity = true; mutation.Restore();
            fault = new(memory) { FailRead = addresses[2] }; var partial = MovementReader.ReadFields(fault, b, c);
            Check(partial[2].Value == null && partial[2].Error != null && partial[0].Value == 6f, "Failed field retains adjacent known facts and explicit error");
            memory.Write(addresses[1], BitConverter.GetBytes(float.NaN)); var nonfinite = MovementReader.ReadFields(memory, b, c);
            Check(nonfinite[1].Value == null && nonfinite[1].Bits != null && nonfinite[0].Value == 6f, "Nonfinite field retains raw bits without fabricating a numeric value"); Reset();
            int count = 0; mutation = new(memory, b, c, 7.8f, valid, (_, _) => { if (++count > 11) throw new IOException("disk failed"); }); mutation.Apply();
            Check(mutation.Restore().Length > 0 && MovementReader.Consistent(MovementReader.ReadFields(memory, b, c)) && Mem.Value(memory, addresses[0], 4) == MovementReader.Bits(6f), "Audit disk failure still permits original-value restoration");
            var phases = new List<string>(); fault = new(memory); mutation = new(fault, b, c, 7.74f, valid, (phase, _) => phases.Add(phase));
            mutation.Apply(); Reset(); bool externalDetected = false;
            try { mutation.Poll(); } catch (InvalidOperationException) { externalDetected = true; }
            Check(externalDetected && phases.Contains("movement-observed"), "External rollback is recorded before poll stops the session");
            int beforeRestore = fault.Writes;
            Check(mutation.Restore().Length == 0 && fault.Writes == beforeRestore && phases.Count(p => p == "movement-restore-already-original") == 5,
                "Already-original fields get explicit no-write restoration records");
        }
        finally { Marshal.FreeHGlobal(allocation); }
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks, scope = "Own allocated native memory only; no game writes; server displacement not verified" }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
