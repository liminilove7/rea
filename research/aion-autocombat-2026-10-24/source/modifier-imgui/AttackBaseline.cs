using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal record AttackState(uint? Interval, uint? Mirror, uint? U, uint? V, float? Scale, string[] Errors)
{
    internal bool Consistent => Errors.Length == 0 && Interval is >= 400 and <= ushort.MaxValue &&
        Interval == Mirror && Interval == U && Interval == V && Scale == 1f;
    internal bool SameValues(AttackState other) => Errors.Length == 0 && other.Errors.Length == 0 &&
        Interval == other.Interval && Mirror == other.Mirror && U == other.U && V == other.V && Scale == other.Scale;
}
internal record AttackBinding(int Pid, long Birth, ulong ModuleBase, ulong Character, uint Interval);
internal record AttackSnapshot(AttackBinding Binding, AttackState State, bool IdentityMatched, Evidence Evidence)
{
    public AttackState ConfirmingState { get; init; }
}

internal static class AttackRules
{
    internal static AttackState Read(IMemory memory, ulong b, ulong c)
    {
        var errors = new List<string>();
        uint? ReadField(string name, ulong address, int width)
        {
            try { return Mem.Value(memory, address, width); }
            catch (Exception e) when (MovementReader.Expected(e)) { errors.Add(name + "：" + e.Message); return null; }
        }
        uint? i = ReadField("interval", b + Profile.Interval, 2), mirror = ReadField("mirror", b + Profile.Mirror, 4),
            u = ReadField("U", c + Profile.U, 2), v = ReadField("V", c + Profile.V, 2), scaleBits = ReadField("scale", c + Profile.Scale, 4);
        float? scale = scaleBits.HasValue ? BitConverter.UInt32BitsToSingle(scaleBits.Value) : null;
        if (scale.HasValue && !float.IsFinite(scale.Value)) { errors.Add("scale非有限值；raw=" + scaleBits); scale = null; }
        return new(i, mirror, u, v, scale, errors.ToArray());
    }
    internal static void CheckContext(IMemory memory, ulong c, uint baseline)
    {
        uint current = Mem.U16(memory, c + Profile.U);
        float scale = BitConverter.ToSingle(memory.Read(c + Profile.Scale, 4));
        if (current != baseline || scale != 1f)
            throw new InvalidOperationException($"武器/动画基线变化（原U={baseline}，现U={current}，系数={scale:R}）；停止，不将新武器恢复成旧间隔。请取消后重新采集。");
    }
    internal static int IntervalForPercent(uint baseline, int reduction)
    {
        if (baseline < 400 || baseline > ushort.MaxValue || reduction < 0 || reduction > 65)
            throw new ArgumentOutOfRangeException(nameof(reduction), "基线需400–65535；间隔缩短比例需0–65%。");
        return Math.Max(400, checked((int)Math.Round(baseline * (100m - reduction) / 100m, MidpointRounding.AwayFromZero)));
    }
    internal static void CheckBinding(AttackBinding expected, Target target, Role role, AttackState current)
    {
        if (expected == null || expected.Pid != target.Pid || expected.Birth != target.Birth ||
            expected.ModuleBase != target.Base || expected.Character != role.Character || !current.Consistent || expected.Interval != current.Interval)
            throw new InvalidOperationException("攻速采样已失效或字段不一致；未写入，请重新采集当前武器基线。");
    }
}

internal static class AttackReader
{
    internal static Observation<AttackSnapshot> Pending() => new(Availability.Unavailable, "先点击“采集当前武器基线”；仅凭武器名称不推定间隔。", null);
    internal static Observation<AttackSnapshot> Fixture(uint baseline) => new(Availability.Ready, "离线模拟基线，不是游戏采样。",
        new(new(1, 0, 0, 0, baseline), new(baseline, baseline, baseline, baseline, 1f, []), true,
            new("Offline UI fixture", DateTimeOffset.UtcNow, "synthetic")));
    internal static Observation<AttackSnapshot> Capture(int pid)
    {
        try
        {
            var target = Target.Capture(pid);
            using var memory = new NativeMemory(pid, target.Path, target.Birth, false);
            var role = Role.Resolve(memory, target.Base, target.Engine);
            var first = AttackRules.Read(memory, target.Base, role.Character);
            bool identity = false; string failure = null;
            AttackState second = null;
            try
            {
                target.Check(); identity = role.Same(Role.Resolve(memory, target.Base, target.Engine));
                second = AttackRules.Read(memory, target.Base, role.Character);
            }
            catch (Exception e) when (MovementReader.Expected(e)) { failure = e.Message; }
            bool ready = identity && first.Consistent && second != null && first.SameValues(second);
            var snapshot = new AttackSnapshot(new(pid, target.Birth, target.Base, role.Character, first.Interval ?? 0),
                first, identity, new("REA既有三字段与U/系数证据；辅助Win32只读两次核对，非原子采样", DateTimeOffset.UtcNow, Profile.GameHash))
                { ConfirmingState = second };
            return new(ready ? Availability.Ready : Availability.Stale,
                failure ?? (ready ? "两次字段一致；作为当前配置基线，不证明无增益或服务器实际攻击频率。" : "字段不一致、采样期间变化或角色身份失配；保留已读值，不能用于写入。"), snapshot);
        }
        catch (Exception e) when (MovementReader.Expected(e)) { return new(Availability.Unavailable, e.Message, null); }
    }
}
