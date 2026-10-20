using System.Text.Json;

namespace AionLab;

internal static class ControllerTests
{
    private sealed class FakeTrial : ITrial
    {
        public double Seconds { get; set; }
        public string LogPath => "synthetic";
        public int Polls, Stops, Disposals;
        public string StopReason;
        public bool FailPoll, FailStop;
        public void Poll() { Polls++; if (FailPoll) throw new IOException("fixture poll failure"); }
        public string[] Stop(string reason) { Stops++; StopReason = reason; if (FailStop) throw new IOException("fixture restore failure"); return []; }
        public void Dispose() { Disposals++; }
    }
    public static void Run(string path)
    {
        var checks = new List<string>();
        void Check(bool value, string label) { if (!value) throw new Exception(label); checks.Add(label); }
        var fake = new FakeTrial();
        int starts = 0;
        using (var c = new LabController((_, _) => { starts++; return fake; }))
        {
            bool rejected = false;
            try { c.Start(0, 700); } catch (ArgumentOutOfRangeException) { rejected = true; }
            Check(rejected && starts == 0, "Missing target never calls core");
            c.Start(1, 700); c.Start(1, 800); c.Tick();
            Check(starts == 1 && fake.Polls == 1 && c.Active, "Duplicate start ignored; active trial polled");
            fake.Seconds = 60; c.Tick(); c.Stop("again");
            Check(!c.Active && fake.Stops == 1 && fake.Disposals == 1, "Timeout restores and disposes exactly once");
        }
        fake = new FakeTrial { FailPoll = true };
        using (var c = new LabController((_, _) => fake))
        {
            c.Start(1, 700); c.Tick();
            Check(!c.Active && fake.Stops == 1 && fake.Disposals == 1, "Poll failure restores and releases");
        }
        fake = new FakeTrial { FailStop = true };
        using (var c = new LabController((_, _) => fake))
        {
            c.Start(1, 700); c.Stop("test");
            Check(!c.Active && fake.Disposals == 1 && c.Status.Contains("未解决"), "Restore failure is visible and handle release attempted");
        }
        fake = new FakeTrial();
        var closing = new LabController((_, _) => fake); closing.Start(1, 700); closing.Dispose();
        Check(fake.Stops == 1 && fake.Disposals == 1, "Window/render exit restores active trial");
        fake = new FakeTrial();
        using (var c = new LabController(movementFactory: (_, _) => fake))
        {
            bool rejected = false;
            try { c.StartMovement(1, float.NaN); } catch (ArgumentOutOfRangeException) { rejected = true; }
            Check(rejected && !c.Active, "Nonfinite movement value cannot start a session");
            c.StartMovement(1, 7.8f); fake.Seconds = 60; c.Tick();
            Check(!c.Active && fake.Stops == 1 && fake.Disposals == 1 && fake.StopReason == "60 秒已到", "Movement timeout passes exact termination cause through lifecycle");
        }
        using (var c = new LabController())
        {
            for (int i = 0; i < 250; i++) c.Log(i.ToString());
            Check(c.Messages.Count == 200, "UI log bounded");
        }
        Check(new PendingMovement().Read().Value == null && new PendingMovement().Read().State == Availability.Unavailable,
            "Movement remains explicitly unavailable");
        Check(new PendingMonsters().Read().Value == null && new PendingMonsters().Read().State == Availability.Unavailable,
            "Unknown monsters do not become an empty live scan");
        var serialized = new JsonCompatibility().Serialize(new { phase = "test", details = new { value = 700 } });
        using var json = JsonDocument.Parse(serialized);
        Check(json.RootElement.GetProperty("details").GetProperty("value").GetInt32() == 700, "Audit JSON retains structured payload");
        File.WriteAllText(path, JsonSerializer.Serialize(new { allPassed = true, checks,
            scope = "Controller fixtures only. Core tests in adjacent .core.json; no live game validation." },
            new JsonSerializerOptions { WriteIndented = true }));
    }
}
