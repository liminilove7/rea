using System.Diagnostics;
using System.Text.Json;
using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal record LifeField(string Name, string Relative, string Address, uint? First, uint? Confirm, string Error);

/// <summary>Client indicators justified by REA; reconstructed amounts are not exact server HP.</summary>
internal record ClientLife(LifeField[] Fields)
{
    public bool Stable => Fields.Length == 6 && Fields.All(f => f.Error == null && f.First.HasValue && f.First == f.Confirm);
    public uint? RawIndicator => Value("Indicator");
    public float? HealthFraction => Stable && RawIndicator is <= 100 ? RawIndicator / 100f : null;
    public bool? ClientDead => !Stable ? null : Value("State2C8") == 7 || (Value("StateAFC") == 18 && Value("FlagAF8") != 0);
    private uint? Value(string name) => Fields.FirstOrDefault(f => f.Name == name)?.First;
}

internal static class LifeReader
{
    internal static bool Expected(Exception e) => e is InvalidDataException || MovementReader.Expected(e);
    private static readonly (string Name, ulong Offset, int Width)[] Layout =
    [ ("Indicator", 0x40, 1), ("State2C8", 0x2C8, 4), ("FlagAF8", 0xAF8, 4),
      ("StateAFC", 0xAFC, 4), ("Reference1358", 0x1358, 4), ("Amount135C", 0x135C, 4) ];

    internal static ClientLife Read(IMemory memory, ulong character)
    {
        var fields = Layout.Select(f => new LifeField(f.Name, "C+" + f.Offset.ToString("X"), Mem.Hex(character + f.Offset), null, null, null)).ToArray();
        for (int pass = 0; pass < 2; pass++)
            for (int i = 0; i < Layout.Length; i++)
            {
                var f = Layout[i];
                try
                {
                    var raw = memory.Read(character + f.Offset, f.Width);
                    uint value = f.Width == 1 ? raw[0] : BitConverter.ToUInt32(raw);
                    fields[i] = pass == 0 ? fields[i] with { First = value } : fields[i] with { Confirm = value };
                }
                catch (Exception e) when (Expected(e))
                { fields[i] = fields[i] with { Error = (fields[i].Error ?? "") + $"读取{pass + 1}：{e.Message}; " }; }
            }
        return new(fields);
    }
}

internal record TargetIdentity(int Pid, long Birth, string ModuleBase, string LocalCharacter,
    ushort Handle, string Entity, string Character, uint Identifier);
internal record TargetHealthSnapshot(int Pid, long Birth, string ModuleBase, string LocalCharacter,
    ushort SelectedBefore, ushort? SelectedAfter, TargetIdentity Binding, string Name,
    ClientLife Life, bool BindingMatched, bool IdentityMatched, string[] Issues, Evidence Evidence)
{
    public ClientActionObservation LocalAction { get; init; }
    public bool Stable => Binding != null && BindingMatched && IdentityMatched && SelectedBefore == SelectedAfter &&
        Life?.Stable == true && Issues.Length == 0;
}

/// <summary>Bounded exact-handle lookup; each capture owns and closes its read-only handle.</summary>
internal static class TargetHealthReader
{
    internal static Observation<TargetHealthSnapshot> Pending() => new(Availability.Unavailable, "尚未采集当前目标生命状态。", null);
    internal static Observation<TargetHealthSnapshot> Capture(int pid, Target validatedTarget = null)
    {
        TargetHealthSnapshot snapshot = null;
        try
        {
            var target = validatedTarget ?? Target.Capture(pid);
            if (target.Pid != pid) throw new InvalidOperationException("验证的会话不属于此PID。");
            target.Check();
            using var memory = new NativeMemory(pid, target.Path, target.Birth, false);
            var role = Role.Resolve(memory, target.Base, target.Engine);
            snapshot = Read(memory, target.Pid, target.Birth, target.Base, role);
            target.Check();
            bool identity = role.Same(Role.Resolve(memory, target.Base, target.Engine));
            snapshot = snapshot with { IdentityMatched = identity };
            return new(snapshot.Stable ? Availability.Ready : Availability.Stale,
                snapshot.Stable ? "当前目标只读采样完成；生命为客户端指示，敌我仍未知。" : "目标为空、读取不完整或绑定发生变化。", snapshot);
        }
        catch (Exception e) when (LifeReader.Expected(e))
        {
            if (snapshot != null) snapshot = snapshot with { IdentityMatched = false, Issues = [.. snapshot.Issues, e.Message] };
            return new(Availability.Unavailable, e.Message, snapshot);
        }
    }

    internal static TargetHealthSnapshot Read(IMemory memory, int pid, long birth, ulong b, Role role)
    {
        var capturedAt = DateTimeOffset.UtcNow;
        ushort before = 0; ushort? after = null; TargetIdentity binding = null; ClientLife life = null;
        string name = null; bool matched = false; var issues = new List<string>();
        try
        {
            before = Mem.U16(memory, b + Profile.LocalHandle + 2);
            if (before != 0)
            {
                ulong manager = Mem.U64(memory, b + Profile.Manager), head = Mem.U64(memory, manager + 0x58);
                byte[] header = memory.Read(head, 48);
                if (header[25] != 1) throw new InvalidDataException("实体树哨兵不匹配。");
                ulong root = BitConverter.ToUInt64(header, 8), node = root;
                var visited = new HashSet<ulong>();
                while (node != head)
                {
                    if (!visited.Add(node) || visited.Count > 128) throw new InvalidDataException("目标查找循环或超过128层预算。");
                    byte[] entry = memory.Read(node, 48);
                    if (entry[25] != 0) throw new InvalidDataException("未识别的实体树节点。");
                    ushort key = BitConverter.ToUInt16(entry, 32);
                    if (key != before) { node = BitConverter.ToUInt64(entry, key > before ? 0 : 16); continue; }
                    ulong entity = BitConverter.ToUInt64(entry, 40), character = Mem.U64(memory, entity + 0x380), vt = Mem.U64(memory, character);
                    if (vt != b + 0xD4F9B0 && vt != b + 0xD53940) throw new InvalidDataException("目标组件类型未验证。");
                    if (Mem.U64(memory, character + 8) != entity) throw new InvalidDataException("目标组件回链不匹配。");
                    uint id = Mem.Value(memory, character + 0x2C, 4);
                    binding = new(pid, birth, Mem.Hex(b), Mem.Hex(role.Character), before, Mem.Hex(entity), Mem.Hex(character), id);
                    life = LifeReader.Read(memory, character);
                    try { name = EntityReader.DecodeName(memory.Read(character + 0x42, 64).Concat(memory.Read(character + 0x82, 64)).ToArray()); }
                    catch (Exception e) when (LifeReader.Expected(e)) { issues.Add("目标名称：" + e.Message); }
                    byte[] confirm = memory.Read(node, 48);
                    matched = confirm.AsSpan(32, 16).SequenceEqual(entry.AsSpan(32, 16)) &&
                        Mem.U64(memory, entity + 0x380) == character && Mem.U64(memory, character) == vt &&
                        Mem.U64(memory, character + 8) == entity && Mem.Value(memory, character + 0x2C, 4) == id &&
                        Mem.U64(memory, b + Profile.Manager) == manager && Mem.U64(memory, manager + 0x58) == head &&
                        Mem.U64(memory, head + 8) == root;
                    if (!matched) issues.Add("目标对象或树绑定在读取期间改变。");
                    break;
                }
                if (binding == null) issues.Add("选中句柄没有找到已验证的角色对象。");
            }
        }
        catch (Exception e) when (LifeReader.Expected(e)) { issues.Add(e.Message); }
        try { after = Mem.U16(memory, b + Profile.LocalHandle + 2); }
        catch (Exception e) when (LifeReader.Expected(e)) { issues.Add("结束目标读取：" + e.Message); }
        return new(pid, birth, Mem.Hex(b), Mem.Hex(role.Character), before, after, binding, name, life, matched, false,
            issues.ToArray(), new("REA UnitIsDead 31F3D0 / ACT_STATE_DEAD 9271C0 / 144480；20261024实测；辅助只读顺序采样，非原子", capturedAt, Profile.GameHash))
            { LocalAction = ActionObservationReader.Read(memory, b, role.Character) };
    }
}

internal record StopAssessment(bool StopRequired, string[] Reasons)
{
    public bool AttackAuthorized => false;
}

/// <summary>Stop observations latch until an explicit new start; this has no attack actuator.</summary>
internal sealed class TargetStopLatch
{
    internal TargetIdentity Anchor { get; private set; }
    internal StopAssessment Assessment { get; private set; } = new(true, ["尚未开始观察"]);
    internal void Start(Observation<TargetHealthSnapshot> observation, DateTimeOffset now)
    {
        Anchor = observation.Value?.Binding;
        Assessment = Evaluate(observation, Anchor, now);
    }
    internal void Update(Observation<TargetHealthSnapshot> observation, DateTimeOffset now)
    {
        if (!Assessment.StopRequired) Assessment = Evaluate(observation, Anchor, now);
    }
    internal void Stop(string reason) => Assessment = new(true, Assessment.StopRequired ? [.. Assessment.Reasons, reason] : [reason]);
    internal static StopAssessment Evaluate(Observation<TargetHealthSnapshot> observation, TargetIdentity anchor, DateTimeOffset now)
    {
        var reasons = new List<string>(); var s = observation.Value;
        if (s == null) return new(true, ["读取不可用：" + observation.Reason]);
        double age = (now - s.Evidence.CapturedAt).TotalSeconds;
        if (age < 0 || age > 2) reasons.Add("样本过期或时间异常");
        if (s.Evidence.BuildIdentity != Profile.GameHash) reasons.Add("版本证据不匹配");
        if (s.SelectedBefore == 0 || s.SelectedAfter == 0) reasons.Add("目标已清空");
        if (s.SelectedBefore != s.SelectedAfter) reasons.Add("采样期间切换目标");
        if (anchor == null || s.Binding != anchor) reasons.Add("对象身份改变或未建立");
        if (anchor != null && (s.SelectedBefore != anchor.Handle || s.SelectedAfter != anchor.Handle)) reasons.Add("选中目标不再是本次对象");
        if (!s.Stable || observation.State != Availability.Ready) reasons.Add("读取失败或状态不稳定");
        if (s.Life?.RawIndicator == 0) reasons.Add("生命指示归零");
        if (s.Life?.RawIndicator is > 100) reasons.Add("生命指示超出验证范围");
        if (s.Life?.ClientDead == true) reasons.Add("客户端死亡判定为真");
        return new(reasons.Count != 0, reasons.ToArray());
    }
}

internal sealed class HealthObservationController(Action<string> log, Func<int, Observation<TargetHealthSnapshot>> capture = null,
    Func<double> monotonic = null) : IDisposable
{
    private readonly Func<int, Observation<TargetHealthSnapshot>> capture = capture;
    private readonly Func<double> monotonic = monotonic ?? (() => Stopwatch.GetTimestamp() / (double)Stopwatch.Frequency);
    private double started, next; private int pid; private StreamWriter journal; private Target validatedTarget;
    internal bool Active { get; private set; }
    internal double Remaining => Active ? Math.Max(0, 60 - (monotonic() - started)) : 0;
    internal Observation<TargetHealthSnapshot> Latest { get; private set; } = TargetHealthReader.Pending();
    internal TargetStopLatch Latch { get; } = new();
    internal void Sample(int selectedPid) { Latest = capture != null ? capture(selectedPid) : TargetHealthReader.Capture(selectedPid, validatedTarget); }
    internal void Start(int selectedPid, string directory)
    {
        if (Active) throw new InvalidOperationException("先停止当前观察。");
        // Hash the selected modules once per explicit observation; check process/module identity each poll.
        // No process handle is retained between polls, and a new explicit start always rehashes.
        validatedTarget = capture == null ? Target.Capture(selectedPid) : null;
        Sample(selectedPid); Latch.Start(Latest, DateTimeOffset.UtcNow);
        if (Latch.Assessment.StopRequired) { validatedTarget = null; log("不能开始观察：" + string.Join("；", Latch.Assessment.Reasons)); return; }
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"target-health-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.jsonl");
        journal = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        try
        {
            pid = selectedPid; started = monotonic(); next = started + .5; Active = true;
            Write("start"); log("当前目标只读观察，最长60秒；日志：" + path);
        }
        catch { Active = false; journal.Dispose(); journal = null; throw; }
    }
    internal void Tick()
    {
        if (!Active) return;
        if (Remaining <= 0) { Stop("观察60秒到期"); return; }
        if (monotonic() < next) return;
        next = monotonic() + .5;
        try
        {
            Sample(pid); Latch.Update(Latest, DateTimeOffset.UtcNow); Write("sample");
            if (Latch.Assessment.StopRequired) Stop("观察停止");
        }
        catch (Exception e) { Stop("观察失败：" + e.Message); }
    }
    private void Write(string kind) => journal?.WriteLine(JsonSerializer.Serialize(new { kind, utc = DateTimeOffset.UtcNow,
        observation = Latest, stop = Latch.Assessment, anchor = Latch.Anchor, gameWrites = 0, automaticInputs = 0 }));
    internal void Stop(string reason)
    {
        Latch.Stop(reason); Active = false; validatedTarget = null;
        try { Write("stop"); }
        finally { journal?.Dispose(); journal = null; log(string.Join("；", Latch.Assessment.Reasons)); }
    }
    public void Dispose() { if (Active || journal != null) Stop("窗口关闭，观察结束"); }
}
