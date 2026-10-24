using System.Diagnostics;
using System.Numerics;
using System.Text;
using AttackSpeedLab;
using NativeMemory = AttackSpeedLab.NativeMemory;

namespace AionLab;

internal record EntityCandidate(ushort Handle, string EntityAddress, string CharacterAddress,
    string RuntimeClass, string NameCandidate, string RawNameHex, uint? TypeCode,
    uint? IdentifierCandidate, Vector3? PositionCandidate, string RawPositionHex,
    float? DistanceCandidate, bool Local, bool TargetHandleMatch, bool BindingMatched, string[] Errors)
{
    public ClientLife Life { get; init; }
    public float? HealthFraction => BindingMatched ? Life?.HealthFraction : null;
    public bool? Hostile => null;
    public bool? Alive => BindingMatched && Life?.ClientDead == true ? false : null;
}

internal record EntitySnapshot(int Pid, long Birth, string ModuleBase, string LocalCharacter,
    ushort LocalHandle, ushort TargetHandleBefore, ushort? TargetHandleAfter,
    int VisitedNodes, int OtherEntities, bool TraversalComplete, bool IdentityMatched,
    EntityCandidate[] Candidates, string[] Issues, Evidence Evidence);

/// <summary>Explicit auxiliary read-only capture of the entity layout supported by saved REA evidence.</summary>
internal static class EntityReader
{
    private static bool Expected(Exception e) => e is InvalidDataException || MovementReader.Expected(e);
    internal static Observation<EntitySnapshot> Pending() => new(Availability.Unavailable,
        "尚未采集。实体表包含普通NPC、玩家和场景物件；未知不等于没有怪物。", null);

    internal static Observation<EntitySnapshot> Capture(int pid)
    {
        try
        {
            var target = Target.Capture(pid);
            using var memory = new NativeMemory(pid, target.Path, target.Birth, false);
            var role = Role.Resolve(memory, target.Base, target.Engine);
            var snapshot = Read(memory, target.Pid, target.Birth, target.Base, target.Engine, role);
            bool identity = false;
            var issues = snapshot.Issues.ToList();
            try { target.Check(); identity = role.Same(Role.Resolve(memory, target.Base, target.Engine)); }
            catch (Exception e) when (Expected(e)) { issues.Add("结束身份核对：" + e.Message); }
            snapshot = snapshot with { IdentityMatched = identity, Issues = issues.ToArray() };
            bool stable = identity && snapshot.TraversalComplete && issues.Count == 0 &&
                snapshot.TargetHandleBefore == snapshot.TargetHandleAfter && snapshot.Candidates.All(x => x.BindingMatched && x.Errors.Length == 0);
            return new(stable ? Availability.Ready : Availability.Stale,
                stable ? "只读采样完成；当前目标含客户端生命指示与死亡判定，敌我与可攻击性仍未知。" :
                "采样部分失败或期间发生变化；保留已读事实，不能用于自动攻击。", snapshot);
        }
        catch (Exception e) when (Expected(e))
        { return new(Availability.Unavailable, e.Message, null); }
    }

    internal static string DecodeName(byte[] raw)
    {
        if (raw.Length % 2 != 0) throw new InvalidDataException("名称字节长度不是UTF-16偶数。");
        int end = -1;
        for (int i = 0; i < raw.Length; i += 2)
            if (raw[i] == 0 && raw[i + 1] == 0) { end = i; break; }
        if (end < 0) throw new InvalidDataException("名称在读取范围内未终止；不显示截断字符串为完整名称。");
        try { return new UnicodeEncoding(false, false, true).GetString(raw, 0, end); }
        catch (DecoderFallbackException e) { throw new InvalidDataException("名称UTF-16无效。", e); }
    }

    internal static Vector3 DecodePosition(byte[] raw)
    {
        if (raw.Length != 12) throw new InvalidDataException("坐标长度不是12字节。");
        var value = new Vector3(BitConverter.ToSingle(raw, 0), BitConverter.ToSingle(raw, 4), BitConverter.ToSingle(raw, 8));
        if (!float.IsFinite(value.X) || !float.IsFinite(value.Y) || !float.IsFinite(value.Z))
            throw new InvalidDataException("坐标包含非有限值，不能计算距离。");
        return value;
    }

    internal static EntitySnapshot Read(IMemory memory, int pid, long birth, ulong b, ulong engine, Role role)
    {
        var rows = new List<EntityCandidate>(); var issues = new List<string>();
        var seen = new HashSet<ulong>(); var keys = new HashSet<ushort>();
        ushort targetBefore = 0; ushort? targetAfter = null;
        int other = 0; bool complete = false;
        void Match(ulong address, string expected)
        {
            if (Convert.ToHexString(memory.Read(address, expected.Length / 2)).ToLowerInvariant() != expected)
                throw new InvalidOperationException("实体布局代码不匹配：" + Mem.Hex(address));
        }
        try
        {
            Match(engine + 0x19190, "488b8180030000c3");
            Match(engine + 0x78D0, "84d27513f7818001000008040000488d812c0600007507488d81ec050000c3cc");
            Match(b + 0x8972F0, "83fa01760a49c7000000000032c0c3498908b001c3");
            targetBefore = Mem.U16(memory, b + Profile.LocalHandle + 2);
            ulong manager = Mem.U64(memory, b + Profile.Manager), head = Mem.U64(memory, manager + 0x58);
            byte[] header = memory.Read(head, 48);
            if (header[25] != 1) throw new InvalidOperationException("实体树哨兵格式不匹配。");
            ulong root = BitConverter.ToUInt64(header, 8);
            var stack = new Stack<ulong>(); stack.Push(root);
            var timer = Stopwatch.StartNew();
            while (stack.Count != 0)
            {
                if (seen.Count >= 4096 || timer.Elapsed.TotalSeconds > 3)
                { issues.Add("达到4096节点或3秒只读预算，保留部分结果；不是实体数量上限。"); break; }
                ulong node = stack.Pop();
                if (node == head) continue;
                if (!seen.Add(node)) { issues.Add("重复树节点，可能有并发变化或循环：" + Mem.Hex(node)); continue; }
                byte[] entry;
                try { entry = memory.Read(node, 48); }
                catch (Exception e) when (Expected(e)) { issues.Add("树节点读取失败：" + e.Message); continue; }
                if (entry[25] != 0) { issues.Add("遇到未识别nil节点：" + Mem.Hex(node)); continue; }
                stack.Push(BitConverter.ToUInt64(entry, 16)); stack.Push(BitConverter.ToUInt64(entry, 0));
                ushort key = BitConverter.ToUInt16(entry, 32);
                if (!keys.Add(key)) issues.Add("重复实体句柄：" + key);
                ulong entity = BitConverter.ToUInt64(entry, 40), character = 0;
                var errors = new List<string>(); string name = null, nameHex = null, positionHex = null, kind = "未确认";
                uint? type = null, identifier = null; Vector3? position = null; bool matched = false; ClientLife life = null;
                try
                {
                    ulong evt = Mem.U64(memory, entity);
                    if (Mem.U64(memory, evt + 0xC0) != engine + 0x19190)
                        throw new InvalidOperationException("实体容器入口不匹配。");
                    character = Mem.U64(memory, entity + 0x380);
                    if (character == 0) { other++; continue; }
                    ulong cvt = Mem.U64(memory, character);
                    if (cvt != b + 0xD4F9B0 && cvt != b + 0xD53940) { other++; continue; }
                    kind = cvt == b + 0xD53940 ? "Player" : "CharacterObject";
                    if (Mem.U64(memory, character + 8) != entity || Mem.U64(memory, evt + 8) != engine + 0x78D0)
                        throw new InvalidOperationException("对象回链或坐标getter不匹配。");
                    void Field(string label, Action read)
                    {
                        try { read(); }
                        catch (Exception e) when (Expected(e)) { errors.Add(label + "：" + e.Message); }
                    }
                    Field("名称", () =>
                    {
                        byte[] raw = memory.Read(character + 0x42, 64).Concat(memory.Read(character + 0x82, 64)).ToArray();
                        nameHex = Convert.ToHexString(raw); name = DecodeName(raw);
                    });
                    Field("类型码", () => type = Mem.Value(memory, character + 0x20, 4));
                    Field("标识", () => identifier = Mem.Value(memory, character + 0x2C, 4));
                    Field("坐标", () => { byte[] raw = memory.Read(entity + 0x5EC, 12); positionHex = Convert.ToHexString(raw); position = DecodePosition(raw); });
                    if (key == targetBefore) life = LifeReader.Read(memory, character);
                    byte[] confirm = memory.Read(node, 48);
                    matched = confirm.AsSpan(32, 16).SequenceEqual(entry.AsSpan(32, 16)) &&
                        Mem.U64(memory, entity + 0x380) == character && Mem.U64(memory, character) == cvt &&
                        Mem.U64(memory, character + 8) == entity && identifier.HasValue &&
                        Mem.Value(memory, character + 0x2C, 4) == identifier;
                    if (life != null && !life.Stable) errors.Add("生命字段读取不完整或前后变化。");
                    if (!matched) errors.Add("读取期间对象绑定变化。");
                }
                catch (Exception e) when (Expected(e)) { errors.Add(e.Message); }
                rows.Add(new(key, Mem.Hex(entity), Mem.Hex(character), kind, name, nameHex, type, identifier,
                    position, positionHex, null, key == role.Handle, key == targetBefore, matched, errors.ToArray()) { Life = life });
            }
            complete = stack.Count == 0 && issues.Count == 0;
            if (Mem.U64(memory, head + 8) != root || Mem.U64(memory, manager + 0x58) != head ||
                Mem.U64(memory, b + Profile.Manager) != manager) issues.Add("实体树根或管理器在采样期间变化。");
            targetAfter = Mem.U16(memory, b + Profile.LocalHandle + 2);
        }
        catch (Exception e) when (Expected(e)) { issues.Add(e.Message); }
        var locals = rows.Where(x => x.Local && x.CharacterAddress == Mem.Hex(role.Character)).ToArray();
        var local = locals.Length == 1 ? locals[0] : null;
        if (local?.PositionCandidate is Vector3 origin)
        {
            rows = rows.Select(x =>
            {
                float? distance = x.PositionCandidate is Vector3 p ? Vector3.Distance(origin, p) : null;
                if (distance.HasValue && !float.IsFinite(distance.Value)) distance = null;
                return x with { DistanceCandidate = distance };
            }).OrderBy(x => x.DistanceCandidate ?? float.PositiveInfinity).ToList();
        }
        else issues.Add("未取得当前角色坐标，距离未知。");
        return new(pid, birth, Mem.Hex(b), Mem.Hex(role.Character), role.Handle, targetBefore, targetAfter,
            seen.Count, other, complete, false, rows.ToArray(), issues.ToArray(),
            new("REA既有实体/目标指令证据 + 20261021字节核对；辅助Win32只读顺序采样，非原子快照", DateTimeOffset.UtcNow, Profile.GameHash));
    }
}
