using System.Diagnostics;
using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal enum SpeedKind { Attack, Movement }
internal record SpeedField(string Name, ulong Address, int Width, uint Baseline, uint Desired);

internal static class SpeedSettings
{
    internal static readonly int[] AttackReductionPresets = [0, 9, 15, 25, 33, 42, 50, 60, 65];
    internal static readonly float[] MovementPresets = [6f, 7f, 7.74f, 7.8f, 9f, 12f, 15f];
    internal static void Validate(SpeedKind kind, float desired)
    {
        if (!Enum.IsDefined(kind) || !float.IsFinite(desired) ||
            (kind == SpeedKind.Attack ? desired < 400 || desired > ushort.MaxValue || desired != MathF.Truncate(desired) : desired < 6 || desired > 15))
            throw new ArgumentOutOfRangeException(nameof(desired), "攻速间隔需400–65535整数且不大于采集基线；移速标度需6–15。这是工具范围，非已验证的游戏上限。");
    }
    internal static SpeedField[] Fields(SpeedKind kind, ulong b, ulong c, float desired, uint? attackBaseline = null)
    {
        Validate(kind, desired);
        if (kind == SpeedKind.Attack)
        {
            if (attackBaseline is not (>= 400 and <= ushort.MaxValue) || desired > attackBaseline.Value)
                throw new ArgumentOutOfRangeException(nameof(attackBaseline), "必须提供当前一致攻速基线，目标不能比基线更慢。");
            return [new("interval", b + Profile.Interval, 2, attackBaseline.Value, (uint)desired),
                new("mirror", b + Profile.Mirror, 4, attackBaseline.Value, (uint)desired),
                new("animationV", c + Profile.V, 2, attackBaseline.Value, (uint)desired)];
        }
        var addresses = MovementReader.Addresses(b, c);
        var baseline = MovementReader.Tuple(6f); var values = MovementReader.Tuple(desired);
        return addresses.Select((address, i) => new SpeedField(MovementReader.Names[i], address, 4, baseline[i], values[i])).ToArray();
    }
}

// Window-owned, explicit maintenance. No service, stealth, automatic reconnect or code patch.
internal sealed class SpeedMutation(IMemory memory, SpeedField[] fields, Action validate, Action<string, object> audit)
{
    private readonly bool[] attempted = new bool[fields.Length];
    private bool started;
    private uint Read(SpeedField f) => Mem.Value(memory, f.Address, f.Width);
    private void Write(SpeedField f, uint value) => memory.Write(f.Address,
        f.Width == 2 ? BitConverter.GetBytes(checked((ushort)value)) : BitConverter.GetBytes(value));
    private void ApplyField(int i, uint before, string cause)
    {
        var f = fields[i];
        validate();
        if (Read(f) != before) throw new InvalidOperationException(f.Name + "写入前再次变化；停止。");
        audit("speed-write-intent", new { cause, f.Name, address = Mem.Hex(f.Address), f.Width, beforeBits = before, desiredBits = f.Desired });
        validate();
        if (Read(f) != before) throw new InvalidOperationException(f.Name + "日志落盘后发生变化；停止。");
        attempted[i] = true;
        Write(f, f.Desired);
        uint actual = Read(f);
        audit("speed-write-readback", new { f.Name, actualBits = actual });
        if (actual != f.Desired) throw new InvalidOperationException(f.Name + "回读不符。");
    }
    internal void Apply()
    {
        if (started) throw new InvalidOperationException("事务不能再次启动。");
        started = true; validate();
        if (fields.Any(f => Read(f) != f.Baseline))
            throw new InvalidOperationException("当前字段与本次采集基线不一致。尚未写入，请重新采集；移速仍要求6.0。");
        audit("speed-baseline", new { fields });
        for (int i = 0; i < fields.Length; i++)
            if (fields[i].Baseline != fields[i].Desired) ApplyField(i, fields[i].Baseline, "initial");
    }
    internal void Poll(bool maintain)
    {
        validate();
        var actual = fields.Select(Read).ToArray();
        if (fields.Select((f, i) => actual[i] == f.Desired).All(v => v)) return;
        audit("speed-external-change", new { actualBits = actual, maintain });
        if (!maintain) throw new InvalidOperationException("检测到外部更新；限时实验停止。");
        for (int i = 0; i < fields.Length; i++)
            if (actual[i] != fields[i].Desired) ApplyField(i, actual[i], "visible-checkbox-maintenance");
    }
    internal string[] Restore()
    {
        var issues = new List<string>();
        void Log(string phase, object detail)
        {
            try { audit(phase, detail); }
            catch (IOException e) { issues.Add("还原日志：" + e.Message); }
        }
        for (int i = fields.Length - 1; i >= 0; i--)
        {
            if (!attempted[i]) continue;
            var f = fields[i];
            try
            {
                validate(); uint current = Read(f);
                if (current == f.Baseline)
                {
                    attempted[i] = false; Log("speed-already-original", new { f.Name, memoryWritten = false }); continue;
                }
                if (current != f.Desired)
                {
                    issues.Add(f.Name + "外部值保留"); Log("speed-external-preserved", new { f.Name, current, memoryWritten = false }); continue;
                }
                Log("speed-restore-intent", new { f.Name, address = Mem.Hex(f.Address), originalBits = f.Baseline });
                validate();
                if (Read(f) != f.Desired) throw new InvalidOperationException("还原前再次变化。");
                Write(f, f.Baseline);
                if (Read(f) != f.Baseline) throw new InvalidOperationException("还原回读失败。");
                attempted[i] = false; Log("speed-restored", new { f.Name, actualBits = f.Baseline });
            }
            catch (Exception e) when (MovementReader.Expected(e)) { issues.Add(f.Name + "：" + e.Message); }
        }
        return issues.ToArray();
    }
}

internal sealed class SpeedTrial : ITrial
{
    private readonly NativeMemory memory;
    private readonly Audit audit;
    private readonly SpeedMutation mutation;
    private readonly bool maintain;
    private readonly Stopwatch clock = new();
    private double nextHeartbeat = 30;
    public double Seconds => clock.Elapsed.TotalSeconds;
    public string LogPath => audit.FileName;
    private SpeedTrial(NativeMemory memory, Audit audit, SpeedMutation mutation, bool maintain)
    { this.memory = memory; this.audit = audit; this.mutation = mutation; this.maintain = maintain; }
    internal static ITrial Begin(int pid, SpeedKind kind, float desired, bool maintain, AttackBinding attackBinding)
    {
        SpeedSettings.Validate(kind, desired);
        var target = Target.Capture(pid);
        NativeMemory memory = null; Audit audit = null; SpeedMutation mutation = null;
        try
        {
            memory = new NativeMemory(pid, target.Path, target.Birth, true);
            var role = Role.Resolve(memory, target.Base, target.Engine);
            uint? attackBaseline = null;
            if (kind == SpeedKind.Attack)
            {
                var state = AttackRules.Read(memory, target.Base, role.Character);
                AttackRules.CheckBinding(attackBinding, target, role, state);
                attackBaseline = state.Interval.Value;
            }
            void Validate()
            {
                target.Check();
                if (!role.Same(Role.Resolve(memory, target.Base, target.Engine)))
                    throw new InvalidOperationException("角色重建；不写旧地址，也不自动重连。");
                if (kind == SpeedKind.Attack) AttackRules.CheckContext(memory, role.Character, attackBaseline.Value);
            }
            audit = new Audit(Path.Combine(AppContext.BaseDirectory, "logs"));
            audit.Record("speed-session", new { pid, target.Path, birthUtc = DateTime.FromFileTimeUtc(target.Birth),
                moduleBase = Mem.Hex(target.Base), character = Mem.Hex(role.Character), gameSHA256 = Profile.GameHash,
                kind = kind.ToString(), desired, attackBaseline, attackBinding, maintain, pollMilliseconds = 500,
                limitSeconds = maintain ? (int?)null : 60, serverEffectVerified = false });
            mutation = new SpeedMutation(memory, SpeedSettings.Fields(kind, target.Base, role.Character, desired, attackBaseline), Validate, audit.Record);
            mutation.Apply();
            var session = new SpeedTrial(memory, audit, mutation, maintain); session.clock.Start(); return session;
        }
        catch (Exception e)
        {
            string[] issues = [];
            try { if (mutation != null) issues = mutation.Restore(); }
            finally { memory?.Dispose(); audit?.Dispose(); }
            throw new InvalidOperationException(e.Message + (issues.Length == 0 ? "；已检查本次写入还原。" : "；还原问题：" + string.Join("；", issues)), e);
        }
    }
    public void Poll()
    {
        mutation.Poll(maintain);
        if (Seconds >= nextHeartbeat)
        {
            audit.Record("speed-heartbeat", new { elapsedSeconds = Seconds, maintain }); nextHeartbeat = Seconds + 30;
        }
    }
    public string[] Stop(string reason)
    {
        var issues = mutation.Restore().ToList();
        try { audit.Record("speed-completed", new { reason, elapsedSeconds = Seconds, issues }); }
        catch (IOException e) { issues.Add("日志：" + e.Message); }
        return issues.ToArray();
    }
    public void Dispose() { memory.Dispose(); audit.Dispose(); }
}

internal sealed class SpeedLocks(Action<string> log, Func<int, SpeedKind, float, bool, AttackBinding, ITrial> factory = null) : IDisposable
{
    private sealed record Running(int Pid, float Desired, bool Maintain, ITrial Trial);
    private readonly Dictionary<SpeedKind, Running> active = [];
    private readonly Func<int, SpeedKind, float, bool, AttackBinding, ITrial> begin = factory ?? SpeedTrial.Begin;
    internal bool Any => active.Count > 0;
    internal bool Active(SpeedKind kind) => active.ContainsKey(kind);
    internal bool Locked(SpeedKind kind) => active.TryGetValue(kind, out var item) && item.Maintain;
    internal string Summary => string.Join(" · ", active.Select(p => $"{(p.Key == SpeedKind.Attack ? "攻速间隔" : "移速")} {p.Value.Desired:0.##} / " +
        (p.Value.Maintain ? "勾选维护中" : $"剩余{Math.Max(0, Math.Ceiling(60 - p.Value.Trial.Seconds))}秒")));
    internal void Start(int pid, SpeedKind kind, float desired, bool maintain, AttackBinding attackBinding = null)
    {
        if (Active(kind)) throw new InvalidOperationException("先取消该项或停止，再选择新档位。");
        SpeedSettings.Validate(kind, desired);
        if (pid <= 0 || active.Values.Any(s => s.Pid != pid)) throw new InvalidOperationException("选择有效目标；两项必须属于同一进程。");
        var trial = begin(pid, kind, desired, maintain, attackBinding);
        active.Add(kind, new(pid, desired, maintain, trial));
        log($"{kind} 已应用 {desired:0.##}；{(maintain ? "窗口运行期间每500ms检查并维护" : "限时60秒")}；日志 {trial.LogPath}");
    }
    internal void Tick()
    {
        foreach (var entry in active.ToArray())
            try
            {
                if (!entry.Value.Maintain && entry.Value.Trial.Seconds >= 60) Stop(entry.Key, "60秒已到");
                else entry.Value.Trial.Poll();
            }
            catch (Exception e) { log(entry.Key + "停止原因：" + e.Message); Stop(entry.Key, "校验/维护失败：" + e.Message); }
    }
    internal void Stop(SpeedKind kind, string reason)
    {
        if (!active.Remove(kind, out var owned)) return;
        var issues = new List<string>();
        try { issues.AddRange(owned.Trial.Stop(reason)); }
        catch (Exception e) { issues.Add(e.Message); }
        finally
        {
            try { owned.Trial.Dispose(); } catch (Exception e) { issues.Add("关闭资源：" + e.Message); }
        }
        log($"{kind} / {reason}：" + (issues.Count == 0 ? "本次写入已还原并回读；句柄关闭。" : "还原存在未解决项：" + string.Join("；", issues)));
    }
    internal void StopAll(string reason) { foreach (var kind in active.Keys.ToArray()) Stop(kind, reason); }
    public void Dispose() => StopAll("关闭窗口或渲染退出");
}
