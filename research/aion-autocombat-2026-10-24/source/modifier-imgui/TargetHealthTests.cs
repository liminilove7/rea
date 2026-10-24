using System.Text.Json;
using AttackSpeedLab;

namespace AionLab;

internal static class TargetHealthTests
{
    private static Observation<TargetHealthSnapshot> From(EntityReaderTests.Fixture fixture)
    {
        var s = TargetHealthReader.Read(fixture, 1, 2, EntityReaderTests.Fixture.B, fixture.Role) with { IdentityMatched = true };
        return new(s.Stable ? Availability.Ready : Availability.Stale, "Synthetic target-health fixture; no game access", s);
    }
    internal static Observation<TargetHealthSnapshot> UiFixture()
    {
        using var fixture = new EntityReaderTests.Fixture(); fixture.SetLife(0, 7, uint.MaxValue, 0);
        return From(fixture);
    }
    internal static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool value, string name) { if (!value) throw new InvalidOperationException(name); checks.Add(name); }
        using var fixture = new EntityReaderTests.Fixture(); var live = From(fixture); var now = DateTimeOffset.UtcNow;
        var anchor = live.Value.Binding;
        Check(live.State == Availability.Ready && live.Value.Life.HealthFraction == 1 && live.Value.Life.ClientDead == false,
            "Exact tree lookup and double field reads preserve the selected living client indicator");
        fixture.SetLife(0, 1, 18, 1); var transition = From(fixture);
        Check(transition.Value.Life.ClientDead == true, "Transitional death branch AFC=18 with AF8!=0 is recognized before state 7");
        fixture.SetLife(0, 7, uint.MaxValue, 0); var corpse = From(fixture);
        Check(corpse.Value.Stable && corpse.Value.SelectedBefore == corpse.Value.SelectedAfter && corpse.Value.Life.ClientDead == true &&
            TargetStopLatch.Evaluate(corpse, anchor, DateTimeOffset.UtcNow).StopRequired,
            "Still-selected retained corpse stops without waiting for disappearance");
        fixture.SetLife(0, 1, uint.MaxValue, 0); var zero = From(fixture);
        Check(zero.Value.Life.ClientDead == false && TargetStopLatch.Evaluate(zero, anchor, DateTimeOffset.UtcNow).StopRequired,
            "Zero indicator stops before death predicate becomes true; not labeled confirmed death");
        fixture.SetLife(100, 7, uint.MaxValue, 0);
        Check(TargetStopLatch.Evaluate(From(fixture), anchor, DateTimeOffset.UtcNow).StopRequired,
            "Death predicate wins over positive health indication");
        fixture.SetLife(255, 0, uint.MaxValue, 0); var invalid = From(fixture);
        Check(invalid.Value.Life.HealthFraction == null && TargetStopLatch.Evaluate(invalid, anchor, DateTimeOffset.UtcNow).StopRequired,
            "Out-of-range health is not clamped to valid health");
        using var missing = new EntityReaderTests.Fixture { MissingLifeField = true }; var partial = From(missing);
        Check(partial.Value.Life.RawIndicator == 100 && partial.Value.Life.ClientDead == null && partial.Value.Life.Fields.Any(f => f.Error != null),
            "One missing death field retains health facts but death and health interpretation stay unknown");
        using var changing = new EntityReaderTests.Fixture { ChangingIndicator = true }; var unstable = From(changing);
        Check(!unstable.Value.Life.Stable && unstable.State == Availability.Stale && unstable.Value.Life.HealthFraction == null,
            "Field changing between reads is preserved and cannot authorize continuation");
        using var reused = new EntityReaderTests.Fixture { RecycleIdentifier = true }; var rebound = From(reused);
        Check(!rebound.Value.BindingMatched && TargetStopLatch.Evaluate(rebound, anchor, DateTimeOffset.UtcNow).StopRequired,
            "Same address reused with a different ID is rejected at the reading boundary");

        void Refuse(TargetHealthSnapshot s, string label) => Check(TargetStopLatch.Evaluate(new(Availability.Ready, "fixture", s), anchor, now).StopRequired, label);
        Refuse(live.Value with { Binding = anchor with { Identifier = anchor.Identifier + 1 } }, "Same handle/name with new ID requires a new explicit observation");
        Refuse(live.Value with { Binding = anchor with { Birth = 3 } }, "PID reuse is detected by process birth identity");
        Refuse(live.Value with { SelectedAfter = 0 }, "Mid-sample deselection stops");
        Refuse(live.Value with { SelectedBefore = 15, SelectedAfter = 15 }, "Another consistently selected handle cannot inherit the anchored target");
        Refuse(live.Value with { Evidence = live.Value.Evidence with { CapturedAt = now.AddSeconds(-3) } }, "Stale snapshot stops");
        Refuse(live.Value with { Evidence = live.Value.Evidence with { CapturedAt = now.AddSeconds(3) } }, "Future timestamp is invalid");
        Refuse(live.Value with { IdentityMatched = false }, "Process or local-role mismatch stops");
        Refuse(live.Value with { Evidence = live.Value.Evidence with { BuildIdentity = "different" } }, "Other binary build cannot share field semantics");
        var latch = new TargetStopLatch(); latch.Start(live, now); latch.Update(corpse, corpse.Value.Evidence.CapturedAt);
        latch.Update(live, now);
        Check(latch.Assessment.StopRequired && !latch.Assessment.AttackAuthorized, "Stop remains latched when later observations look healthy");
        latch.Start(live, now);
        Check(!latch.Assessment.StopRequired && !latch.Assessment.AttackAuthorized, "Only explicit start resets latch, without granting attack authority");

        double time = 0; var current = live; var messages = new List<string>();
        string directory = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path)), "health-controller-fixture");
        using (var controller = new HealthObservationController(messages.Add, _ => current, () => time))
        {
            controller.Start(1, directory); current = corpse; time = .6; controller.Tick();
            Check(!controller.Active && controller.Latch.Assessment.StopRequired, "Controller releases observer immediately on retained corpse");
            current = live; time = .7; controller.Tick();
            Check(!controller.Active, "Later healthy target cannot automatically restart controller");
            controller.Start(1, directory); time = 61; controller.Tick();
            Check(!controller.Active && controller.Latch.Assessment.Reasons.Any(r => r.Contains("60秒")), "Observation ends at its monotonic deadline");
            time = 62; controller.Start(1, directory); controller.Dispose();
            Check(!controller.Active, "Window disposal ends observation");
        }
        foreach (string file in Directory.GetFiles(directory, "*.jsonl"))
            using (new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        Check(true, "All completed observer journal handles are released");
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks,
            scope = "Synthetic memory/tree failures and observer lifecycle; no game write or attack execution." }, new JsonSerializerOptions { WriteIndented = true }));
    }

    internal static void Replay(string inputDirectory, string output)
    {
        string[] names = ["health-stop-kill-series.json", "health-stop-player-kill-series.json",
            "health-stop-quest-kill-series.json", "health-stop-retained-corpse.json"];
        int[] expectedSelectedDead = [0, 12, 11, 41];
        var reports = new List<object>(); int total = 0;
        for (int index = 0; index < names.Length; index++)
        {
            string name = names[index]; string source = Path.Combine(inputDirectory, name);
            using var doc = JsonDocument.Parse(File.ReadAllText(source)); var root = doc.RootElement;
            var latch = new TargetStopLatch(); bool started = false, stopped = false; int count = 0, selectedDead = 0;
            foreach (var r in root.GetProperty("samples").EnumerateArray())
            {
                var o = r.GetProperty("anchorObject"); var utc = r.GetProperty("utc").GetDateTimeOffset();
                TargetIdentity binding = null; ClientLife life = null; string targetName = null;
                if (o.ValueKind == JsonValueKind.Object)
                {
                    binding = new(1, 2, "recorded-build", "recorded-local", o.GetProperty("handle").GetUInt16(),
                        o.GetProperty("entity").GetString(), o.GetProperty("character").GetString(), o.GetProperty("identifier").GetUInt32());
                    targetName = o.GetProperty("name").GetString(); var v = o.GetProperty("values");
                    (string Name, string Key)[] mapping = [("Indicator", "byte40"), ("State2C8", "state2c8"),
                        ("StateAFC", "stateafc"), ("FlagAF8", "flagaf8"), ("Reference1358", "reference1358"), ("Amount135C", "amount135c")];
                    life = new(mapping.Select(m =>
                    {
                        uint first = v.GetProperty(m.Key).GetUInt32();
                        bool consistent = o.GetProperty("rawBefore").GetProperty(m.Key).GetString() == o.GetProperty("rawAfter").GetProperty(m.Key).GetString();
                        return new LifeField(m.Name, "recorded", "recorded", first, consistent ? first : null, consistent ? null : "changed");
                    }).ToArray());
                }
                ushort before = r.GetProperty("selectedBefore").GetUInt16(), after = r.GetProperty("selectedAfter").GetUInt16();
                bool stable = r.GetProperty("stable").GetBoolean();
                var s = new TargetHealthSnapshot(1, 2, "recorded-build", "recorded-local", before, after, binding, targetName,
                    life, stable, stable, [], new("Recorded auxiliary capture replay", utc, Profile.GameHash));
                var observation = new Observation<TargetHealthSnapshot>(s.Stable ? Availability.Ready : Availability.Stale, "replay", s);
                if (!started) { latch.Start(observation, utc); started = true; } else latch.Update(observation, utc);
                if (stopped && !latch.Assessment.StopRequired) throw new InvalidDataException("Stopped observation resumed: " + name);
                stopped |= latch.Assessment.StopRequired;
                if (life?.ClientDead == true && binding != null && before == binding.Handle && binding == latch.Anchor) selectedDead++;
                if (binding != latch.Anchor || before == 0 || before != after || life?.RawIndicator == 0 || life?.ClientDead == true)
                    if (!latch.Assessment.StopRequired) throw new InvalidDataException("Missed stop: " + name);
                if (latch.Assessment.AttackAuthorized) throw new InvalidDataException("Replay granted attack authority");
                count++;
            }
            if (selectedDead != expectedSelectedDead[index]) throw new InvalidDataException($"Selected corpse replay mismatch {name}: {selectedDead}");
            total += count;
            reports.Add(new { source = name, sha256 = Target.Hash(source), samples = count, selectedDead, latched = latch.Assessment.StopRequired });
        }
        File.WriteAllText(output, JsonSerializer.Serialize(new { allPassed = true, samples = total, captures = reports,
            scope = "C# production stop-latch replay of saved auxiliary captures; no target access or attack execution." }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
