using System.Text.Json;
using AttackSpeedLab;

namespace AionLab;

internal static class ActionObservationTests
{
    private sealed class Fixture : IMemory
    {
        internal const ulong B=0x10000000, C=0x400000;
        internal readonly Dictionary<ulong,uint> Values=new()
        {
            [C+0x1690]=1,[C+0x1694]=6,[C+0x16A0]=0,[C+0x16A4]=0,[C+0x16A8]=0,
            [C+0x16AC]=1,[C+0x1E90]=1234,[C+0x1ED8]=0,[C+0x1104]=12,
            [B+0x146F388]=0
        };
        internal bool ChangeCounter, FailPending; private int counterReads;
        public byte[] Read(ulong address,int count)
        {
            if(count!=4) throw new InvalidOperationException("Only scalar DWORD observations expected");
            if(FailPending && address==B+0x146F388) throw new IOException("Unavailable transport scalar");
            if(!Values.TryGetValue(address,out uint value)) throw new IOException("Unexpected field address");
            if(ChangeCounter && address==C+0x1104 && ++counterReads>1) value++;
            return BitConverter.GetBytes(value);
        }
        public void Write(ulong address,byte[] bytes)=>throw new InvalidOperationException("Read-only action observer wrote memory");
        public void Dispose() { }
        internal ClientActionObservation Capture()=>ActionObservationReader.Read(this,B,C);
    }
    internal static void Run(string path)
    {
        var checks=new List<string>();
        void Check(bool passed,string label){if(!passed)throw new InvalidOperationException(label);checks.Add(label);}
        using var f=new Fixture();var s=f.Capture();
        Check(s.Stable && s.GoalKind==1 && s.GoalPhase==6 && s.AttackRequestCounter==12,
            "Action state, substate and request counter are separate DWORD facts");
        Check(s.Fields.Single(x=>x.Name=="PendingTransportBytes").Address==Mem.Hex(Fixture.B+0x146F388),
            "Transport pending scalar is relative to LEA global object address, not its first qword");
        f.Values[Fixture.C+0x1690]=9;
        Check(f.Capture().GoalBranch.Contains("条件"),"Movement/attack mode is described as conditional, not guaranteed attack");
        using var changed=new Fixture{ChangeCounter=true};var unstable=changed.Capture();
        var counter=unstable.Fields.Single(x=>x.Name=="AttackRequestCounter");
        Check(!unstable.Stable && counter.First==12 && counter.Confirm==13,
            "Concurrent request change preserves both reads and rejects stable interpretation");
        using var failed=new Fixture{FailPending=true};var partial=failed.Capture();
        Check(!partial.Stable && partial.GoalKind==1 && partial.Fields.Single(x=>x.Name=="PendingTransportBytes").Error!=null,
            "Unavailable transport scalar preserves character action facts and its own error");
        using var document=JsonDocument.Parse(JsonSerializer.Serialize(unstable));
        Check(document.RootElement.GetProperty("Fields").EnumerateArray().Any(x=>x.GetProperty("First").GetUInt32()==12 &&
              x.GetProperty("Confirm").GetUInt32()==13),"JSON boundary preserves changing raw request facts");
        File.WriteAllText(path,JsonSerializer.Serialize(new{allPassed=true,checks,
            scope="Read-only scalar fixtures; no target call, keyboard action or server hit assertion."},new JsonSerializerOptions{WriteIndented=true}));
    }
}
