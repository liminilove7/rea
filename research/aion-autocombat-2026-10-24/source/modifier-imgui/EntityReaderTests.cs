using System.Text;
using System.Text.Json;
using AttackSpeedLab;

namespace AionLab;

internal static class EntityReaderTests
{
    internal sealed class Fixture : IMemory
    {
        internal const ulong B = 0x10000000, Engine = 0x20000000, Manager = 0x300000,
            Head = 0x301000, Root = 0x302000, PlayerNode = 0x303000, SceneNode = 0x304000,
            NpcEntity = 0x310000, PlayerEntity = 0x320000, SceneEntity = 0x330000,
            Npc = 0x410000, Player = 0x420000, Vt = 0x500000;
        private readonly Dictionary<ulong, byte[]> regions = new();
        internal bool RecycleNpc, BadPosition, BrokenChild;
        internal bool MissingLifeField, ChangingIndicator, RecycleIdentifier;
        private int indicatorReads, identifierReads;
        private int npcReads;
        internal Role Role => new() { Handle = ushort.MaxValue, Entity = PlayerEntity, Character = Player, Node = PlayerNode };
        internal Fixture()
        {
            Add(B + Profile.Manager, BitConverter.GetBytes(Manager));
            Add(B + Profile.LocalHandle, [255, 255, 14, 0]);
            Add(Manager + 0x58, BitConverter.GetBytes(Head));
            var h = new byte[48]; Put(h, 8, Root); h[25] = 1; Add(Head, h);
            Add(Root, Node(14, NpcEntity, SceneNode, PlayerNode));
            Add(PlayerNode, Node(ushort.MaxValue, PlayerEntity, Head, Head));
            Add(SceneNode, Node(2, SceneEntity, Head, Head));
            Add(Engine + 0x19190, Convert.FromHexString("488b8180030000c3"));
            Add(Engine + 0x78D0, Convert.FromHexString("84d27513f7818001000008040000488d812c0600007507488d81ec050000c3cc"));
            Add(B + 0x8972F0, Convert.FromHexString("83fa01760a49c7000000000032c0c3498908b001c3"));
            var vt = new byte[0xc8]; Put(vt, 8, Engine + 0x78D0); Put(vt, 0xc0, Engine + 0x19190); Add(Vt, vt);
            AddEntity(NpcEntity, Npc, 3, 4); AddEntity(PlayerEntity, Player, 0, 0); AddEntity(SceneEntity, 0, 0, 0);
            AddCharacter(Npc, NpcEntity, B + 0xD4F9B0, "怪物%候选", 2);
            AddCharacter(Player, PlayerEntity, B + 0xD53940, "测试角色", 1);
            SetLife(100, 0, uint.MaxValue, 0);
        }
        internal void SetLife(byte indicator, uint state, uint afc, uint af8)
        {
            regions[Npc + 0x40] = [indicator];
            regions[Npc + 0x2C8] = BitConverter.GetBytes(state);
            regions[Npc + 0xAFC] = BitConverter.GetBytes(afc);
            regions[Npc + 0xAF8] = BitConverter.GetBytes(af8);
            regions[Npc + 0x1358] = BitConverter.GetBytes(500u);
            regions[Npc + 0x135C] = BitConverter.GetBytes((uint)indicator * 5);
            regions[Npc][0x40] = indicator;
        }
        private static void Put(byte[] raw, int off, ulong value) => BitConverter.GetBytes(value).CopyTo(raw, off);
        private static byte[] Node(ushort key, ulong entity, ulong left, ulong right)
        {
            var raw = new byte[48]; Put(raw, 0, left); Put(raw, 16, right); Put(raw, 40, entity);
            BitConverter.GetBytes(key).CopyTo(raw, 32); return raw;
        }
        private void AddEntity(ulong address, ulong character, float x, float y)
        {
            var raw = new byte[0x600]; Put(raw, 0, Vt); Put(raw, 0x380, character);
            BitConverter.GetBytes(x).CopyTo(raw, 0x5ec); BitConverter.GetBytes(y).CopyTo(raw, 0x5f0); Add(address, raw);
        }
        private void AddCharacter(ulong address, ulong entity, ulong vt, string name, uint type)
        {
            var raw = new byte[256]; Put(raw, 0, vt); Put(raw, 8, entity); BitConverter.GetBytes(type).CopyTo(raw, 0x20);
            Encoding.Unicode.GetBytes(name + "\0").CopyTo(raw, 0x42); Add(address, raw);
        }
        private void Add(ulong address, byte[] data) => regions.Add(address, data);
        public byte[] Read(ulong address, int count)
        {
            if (count is < 1 or > 64) throw new ArgumentOutOfRangeException(nameof(count));
            if (address == NpcEntity + 0x5ec && BadPosition)
            { var bad = new byte[12]; BitConverter.GetBytes(float.NaN).CopyTo(bad, 0); return bad; }
            if (address == SceneNode && BrokenChild) throw new IOException("Synthetic unreadable child");
            if (address == Npc + 0xAF8 && MissingLifeField) throw new IOException("Synthetic missing life field");
            if (address == Npc + 0x40 && count == 1 && ChangingIndicator && ++indicatorReads >= 2) return [0];
            if (address == Npc + 0x2C && RecycleIdentifier && ++identifierReads >= 2) return BitConverter.GetBytes(999u);
            foreach (var region in regions)
                if (address >= region.Key && address + (ulong)count <= region.Key + (ulong)region.Value.Length)
                {
                    var value = region.Value.AsSpan(checked((int)(address - region.Key)), count).ToArray();
                    if (address == Root && count == 48 && RecycleNpc && ++npcReads >= 2) Put(value, 40, SceneEntity);
                    return value;
                }
            throw new IOException("Synthetic unmapped address: " + address.ToString("x"));
        }
        public void Write(ulong address, byte[] value) => throw new InvalidOperationException("Read-only reader attempted write");
        public void Dispose() { }
        internal EntitySnapshot Capture() => EntityReader.Read(this, 1, 2, B, Engine, Role);
    }

    internal static Observation<EntitySnapshot> UiFixture()
    {
        using var fixture = new Fixture();
        return new(Availability.Ready, "离线合成实体夹具；不是游戏采样。", fixture.Capture() with
        { Evidence = new("Synthetic UI fixture", DateTimeOffset.UtcNow, "synthetic") });
    }

    internal static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool condition, string name) { if (!condition) throw new InvalidOperationException(name); checks.Add(name); }
        bool Invalid(Action action) { try { action(); return false; } catch (InvalidDataException) { return true; } }
        using var fixture = new Fixture(); var snapshot = fixture.Capture();
        Check(snapshot.TraversalComplete && snapshot.VisitedNodes == 3 && snapshot.OtherEntities == 1 && snapshot.Candidates.Length == 2,
            "Entity tree distinguishes an unpopulated scene entity from two character candidates");
        var npc = snapshot.Candidates.Single(x => x.TargetHandleMatch);
        Check(npc.NameCandidate == "怪物%候选" && npc.DistanceCandidate == 5 && npc.BindingMatched,
            "UTF16 name and entity-position getter compose into selected-handle candidate and distance");
        Check(npc.HealthFraction == 1 && npc.Alive == null && npc.Hostile == null && npc.Life.ClientDead == false,
            "Client health indicator is explicit; non-dead does not imply attackable or hostile");
        using var recycled = new Fixture { RecycleNpc = true }; var changed = recycled.Capture();
        Check(changed.Candidates.Any(x => x.TargetHandleMatch && !x.BindingMatched && x.Errors.Length != 0),
            "Recycled entity binding preserves observed fields but is marked changed");
        using var partial = new Fixture { BrokenChild = true }; var incomplete = partial.Capture();
        Check(!incomplete.TraversalComplete && incomplete.Candidates.Length == 2 && incomplete.Issues.Any(x => x.Contains("Synthetic")),
            "Unreadable child preserves other collected entities and explicit partial coverage");
        using var nan = new Fixture { BadPosition = true }; var unknown = nan.Capture().Candidates.Single(x => x.TargetHandleMatch);
        Check(unknown.PositionCandidate == null && unknown.DistanceCandidate == null && unknown.NameCandidate != null && unknown.Errors.Length > 0,
            "Invalid coordinates preserve a readable name and remain unknown rather than distance zero");
        Check(Invalid(() => EntityReader.DecodeName([65, 0, 66, 0])) &&
            Invalid(() => EntityReader.DecodeName([0, 216, 0, 0])), "Unterminated and malformed UTF16 stay invalid");
        string json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { IncludeFields = true });
        using var document = JsonDocument.Parse(json);
        Check(document.RootElement.GetProperty("Candidates")[0].GetProperty("PositionCandidate").TryGetProperty("X", out _) &&
            document.RootElement.GetProperty("Candidates").EnumerateArray().Any(x => x.GetProperty("HealthFraction").ValueKind == JsonValueKind.Null),
            "Serialized boundary retains coordinate components and unknown health for unobserved entities");
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks, scope = "Synthetic entity-tree/error boundaries; no native target access." },
            new JsonSerializerOptions { WriteIndented = true }));
    }
}
