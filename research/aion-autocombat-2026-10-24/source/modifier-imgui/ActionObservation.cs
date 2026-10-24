using AttackSpeedLab;

namespace AionLab;

/// <summary>Client action-state observations; no callback, queue mutation or send operation.</summary>
internal record ClientActionObservation(LifeField[] Fields, string Source)
{
    public bool Stable => Fields.Length == ActionObservationReader.FieldCount &&
        Fields.All(f => f.Error == null && f.First.HasValue && f.First == f.Confirm);
    public uint? GoalKind => Value("GoalKind");
    public uint? GoalPhase => Value("GoalPhase");
    public uint? AttackRequestCounter => Value("AttackRequestCounter");
    public uint? PendingTransportBytes => Value("PendingTransportBytes");
    public string GoalBranch => !Stable ? "字段不稳定/未知" : GoalKind switch
    { 1 => "普通攻击处理分支", 9 or 10 => "移动处理后条件进入攻击分支", _ => "其他动作值，未完整命名" };
    private uint? Value(string name) => Fields.SingleOrDefault(f => f.Name == name)?.First;
}

internal static class ActionObservationReader
{
    private static readonly (string Name, ulong Offset)[] CharacterFields =
    [ ("GoalKind",0x1690), ("GoalPhase",0x1694), ("ContinuationKind",0x16A0),
      ("ResumeGoal",0x16A4), ("ResumePhase",0x16A8), ("GoalArgument5",0x16AC),
      ("LastAttackAttemptTick",0x1E90), ("AttackRelatedFlag",0x1ED8), ("AttackRequestCounter",0x1104) ];
    internal static int FieldCount => CharacterFields.Length + 1;

    internal static ClientActionObservation Read(IMemory memory, ulong b, ulong localCharacter)
    {
        var fields = CharacterFields.Select(f => new LifeField(f.Name, "C+" + f.Offset.ToString("X"),
            Mem.Hex(localCharacter + f.Offset), null, null, null)).ToList();
        // REA instructions: LEA RCX,B+145EED0; 7CFBF0 accesses this+104B8.
        fields.Add(new("PendingTransportBytes", "B+145EED0+104B8", Mem.Hex(b + 0x145EED0 + 0x104B8), null, null, null));
        var addresses = CharacterFields.Select(f => localCharacter + f.Offset).Append(b + 0x145EED0 + 0x104B8).ToArray();
        for (int pass=0; pass<2; pass++)
            for (int i=0; i<fields.Count; i++)
                try
                {
                    uint value=Mem.Value(memory,addresses[i],4);
                    fields[i]=pass==0 ? fields[i] with { First=value } : fields[i] with { Confirm=value };
                }
                catch (Exception e) when (LifeReader.Expected(e))
                { fields[i]=fields[i] with { Error=(fields[i].Error ?? "")+$"读取{pass+1}：{e.Message}; " }; }
        return new(fields.ToArray(), "REA：force_attack分支53C260→151A90→116470写动作状态；Player回调1652A0分派→144F10→16D600；执行线程与快捷键1映射待证实");
    }
}
