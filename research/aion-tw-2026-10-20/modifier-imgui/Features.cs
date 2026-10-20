using System.Numerics;
using System.Text.Json;
using AttackSpeedLab;

namespace AionLab;

// Match the original serializer's public-field support; no private fields are exported.
internal sealed class JsonCompatibility
{
    private static readonly JsonSerializerOptions Options = new() { IncludeFields = true };
    public string Serialize(object value) => JsonSerializer.Serialize(value, Options);
}

internal enum Availability { Unavailable, Ready, Stale }
internal record Evidence(string Source, DateTimeOffset CapturedAt, string BuildIdentity);
internal record MovementSnapshot(float? Speed, string Unit, Evidence Evidence);
internal record MonsterSnapshot(string Id, string Name, string Classification,
    Vector3? Position, float? Distance, float? HealthFraction, Evidence Evidence);
internal record Observation<T>(Availability State, string Reason, T Value);

// Future adapters publish validated snapshots. Missing facts stay null.
// The monster contract is read-only and contains no targeting/automation actions.
internal interface IMovementSource { Observation<MovementSnapshot> Read(); }
internal interface IMonsterSource { Observation<IReadOnlyList<MonsterSnapshot>> Read(); }
internal sealed class PendingMovement : IMovementSource
{
    public Observation<MovementSnapshot> Read() => new(Availability.Unavailable,
        "尚未验证地址、字段类型、单位和还原条件。", null);
}
internal sealed class PendingMonsters : IMonsterSource
{
    public Observation<IReadOnlyList<MonsterSnapshot>> Read() => new(Availability.Unavailable,
        "尚未接入实体快照；未知不等于附近没有怪物。", null);
}

internal interface ITrial : IDisposable
{
    double Seconds { get; }
    string LogPath { get; }
    void Poll();
    string[] Stop();
}
internal sealed class ExistingTrial(Session session) : ITrial
{
    public double Seconds => session.Elapsed.Elapsed.TotalSeconds;
    public string LogPath => session.LogPath;
    public void Poll() => session.Poll();
    public string[] Stop() => session.Stop();
    public void Dispose() => session.Dispose();
}

// Owns trial lifetime independently of selected page and rendering.
internal sealed class LabController : IDisposable
{
    private readonly Func<int, uint, ITrial> begin;
    private ITrial active;
    private readonly Queue<string> messages = new();
    public IReadOnlyCollection<string> Messages => messages;
    public bool Active => active != null;
    public double Remaining => active == null ? 0 : Math.Max(0, 60 - active.Seconds);
    public string Status { get; private set; } = "未连接 · 尚未读写游戏";
    public LabController(Func<int, uint, ITrial> factory = null)
    {
        begin = factory ?? ((pid, desired) => new ExistingTrial(Session.Begin(pid, desired,
            Path.Combine(AppContext.BaseDirectory, "logs"))));
    }
    public void Log(string text)
    {
        messages.Enqueue($"{DateTime.Now:HH:mm:ss}  {text}");
        while (messages.Count > 200) messages.Dequeue();
    }
    public void Start(int pid, int desired)
    {
        if (Active) return;
        if (pid <= 0 || desired < 700 || desired > 1200)
            throw new ArgumentOutOfRangeException(nameof(desired), "请先选择目标，间隔范围为 700–1200。");
        active = begin(pid, (uint)desired);
        Status = "实验中 · 最长 60 秒";
        Log($"已应用间隔 {desired}；日志：{active.LogPath}");
    }
    public void Tick()
    {
        if (!Active) return;
        try
        {
            if (active.Seconds >= 60) { Stop("60 秒已到"); return; }
            active.Poll();
        }
        catch (Exception e) { Log(e.Message); Stop("校验失败"); }
    }
    public void Stop(string reason)
    {
        var owned = active;
        active = null;
        if (owned == null) return;
        var issues = new List<string>();
        try { issues.AddRange(owned.Stop()); }
        catch (Exception e) { issues.Add(e.Message); }
        finally
        {
            try { owned.Dispose(); }
            catch (Exception e) { issues.Add("释放资源：" + e.Message); }
        }
        Status = issues.Count == 0 ? "已还原 · 回读确认" : "还原存在未解决项 · 请检查日志";
        Log(reason + "：" + (issues.Count == 0 ? "原值已回读确认。" : string.Join("；", issues)));
    }
    public void Dispose() => Stop("关闭窗口或渲染退出");
}
