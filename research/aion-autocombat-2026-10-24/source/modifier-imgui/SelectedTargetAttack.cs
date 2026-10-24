using System.Diagnostics;
using System.Runtime.InteropServices;
using AttackSpeedLab;

namespace AionLab;

internal enum AttackInputState { Idle, Preparing, Running, Completed, Cancelled, Failed }
internal record AttackKey(string Name, ushort VirtualKey);
internal record KiteMovement(ushort LeftKey, ushort RightKey, double StepSeconds);

internal interface ISelectedAttackSession : IDisposable
{
    bool IsForeground();
    bool StopRequested();
    void SendAttackOnce(ushort key);
    void HoldMovement(ushort key);
    void ReleaseMovement();
}

internal static class AttackKeys
{
    internal static readonly AttackKey[] Choices = Enumerable.Range('A', 26).Select(k => new AttackKey(((char)k).ToString(), (ushort)k))
        .Concat(Enumerable.Range('0', 10).Select(k => new AttackKey(((char)k).ToString(), (ushort)k)))
        .Concat(Enumerable.Range(0, 12).Select(k => new AttackKey("F" + (k + 1), (ushort)(0x70 + k)))).Where(k => k.VirtualKey != 0x77).ToArray();
    internal static bool Supported(ushort key) => Choices.Any(k => k.VirtualKey == key);
}

// A visible, bounded test of the user's configured attack key. No autonomous target selection.
internal sealed class SelectedAttackController(Action<string> log, Func<int, ushort, double, KiteMovement, ISelectedAttackSession> factory = null,
    Func<double> time = null) : IDisposable
{
    private readonly Func<int, ushort, double, KiteMovement, ISelectedAttackSession> begin = factory ?? ForegroundAttackSession.Begin;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly Func<double> now = time;
    private ISelectedAttackSession session;
    private ushort key;
    private double deadline;
    private double end, nextKey, interval;
    private double nextMove;
    private KiteMovement movement;
    private bool movingLeft;
    internal int SentCount { get; private set; }
    internal AttackInputState State { get; private set; }
    internal string Status { get; private set; } = "待启动；没有发送按键。";
    internal bool Preparing => State == AttackInputState.Preparing;
    internal bool Active => State is AttackInputState.Preparing or AttackInputState.Running;
    internal bool CleanupPending => !Active && session != null;
    private double Time => now == null ? clock.Elapsed.TotalSeconds : now();
    internal double Remaining => Active ? Math.Max(0, (Preparing ? deadline : end) - Time) : 0;
    internal void Arm(int pid, ushort attackKey, double repeatSeconds = 2.5, KiteMovement movementPlan = null)
    {
        if (Active || session != null) throw new InvalidOperationException("已有测试或未解决的按键释放；先停止并处理。");
        if (pid <= 0 || !AttackKeys.Supported(attackKey) || !double.IsFinite(repeatSeconds) || repeatSeconds < .5 || repeatSeconds > 10)
            throw new ArgumentException("请选择游戏目标和攻击单键，重复间隔需0.5–10秒。");
        if (movementPlan != null && (!AttackKeys.Supported(movementPlan.LeftKey) || !AttackKeys.Supported(movementPlan.RightKey) ||
            movementPlan.LeftKey == movementPlan.RightKey || movementPlan.LeftKey == attackKey || movementPlan.RightKey == attackKey ||
            !double.IsFinite(movementPlan.StepSeconds) || movementPlan.StepSeconds < .25 || movementPlan.StepSeconds > 2))
            throw new ArgumentException("横移需要两个不同的已支持按键，且不能与攻击/停止键重合；每向0.25–2秒。");
        double current = Time;
        if (!double.IsFinite(current)) throw new InvalidOperationException("计时器不可用。");
        session = begin(pid, attackKey, repeatSeconds, movementPlan); key = attackKey; deadline = current + 5;
        interval = repeatSeconds; movement = movementPlan; SentCount = 0; movingLeft = true;
        State = AttackInputState.Preparing;
        Status = $"5秒内切回游戏并保持已选怪物；每{interval:0.##}秒按一次，最长30秒。F8/切窗停止。";
        log(Status);
    }
    internal void Tick()
    {
        if (!Active) return;
        try
        {
            double current = Time;
            if (!double.IsFinite(current)) throw new InvalidOperationException("计时器不可用。");
            if (session.StopRequested()) { Cancel("F8停止，后续按键已取消。"); return; }
            if (Preparing && current < deadline) return;
            if (!session.IsForeground()) { Cancel("到时游戏没有前台焦点，未发送按键。"); return; }
            if (Preparing) { State = AttackInputState.Running; end = current + 30; nextKey = current; nextMove = current; }
            if (current >= end) { State = AttackInputState.Completed; Status = $"30秒测试结束，共发送{SentCount}次；后续按键已停止。"; log(Status); return; }
            if (movement != null && current >= nextMove)
            {
                session.ReleaseMovement();
                session.HoldMovement(movingLeft ? movement.LeftKey : movement.RightKey);
                movingLeft = !movingLeft; nextMove = current + movement.StepSeconds;
            }
            if (current < nextKey) return;
            // A partial input/audit failure must never cause retries or catch-up bursts.
            State = AttackInputState.Failed;
            session.SendAttackOnce(key);
            SentCount++; nextKey = current + interval; State = AttackInputState.Running;
            Status = $"已发送{SentCount}次攻击键；系统接受输入不等于游戏命中。F8/切窗停止。";
        }
        catch (Exception e) { State = AttackInputState.Failed; Status = "本次停止：" + e.Message + "；不会自动重发。"; log(Status); }
        finally { if (!Active) Release(); }
    }
    private void Release()
    {
        var owned = session;
        if (owned == null) return;
        try { owned.Dispose(); session = null; if (State == AttackInputState.Failed) Status += "；输入会话已释放。"; }
        catch (Exception e) { State = AttackInputState.Failed; Status = "按键释放/会话关闭存在未解决项：" + e.Message; log(Status); }
    }
    internal void Cancel(string reason)
    {
        if (!Active) return;
        State = AttackInputState.Cancelled; Status = reason; Release(); log(Status);
    }
    public void Dispose() { Cancel("窗口关闭，取消未发送的按键。"); Release(); }
    internal void RetryCleanup() { if (!Active) Release(); }
}

internal sealed class ForegroundAttackSession : ISelectedAttackSession
{
    private readonly Target target;
    private readonly Audit audit;
    private readonly OwnedKeyEmitter keys;
    private ushort? movementScan;
    private bool faulted;
    private ForegroundAttackSession(Target target, Audit audit)
    {
        this.target = target; this.audit = audit;
        keys = new OwnedKeyEmitter(packets =>
        {
            Marshal.SetLastPInvokeError(0);
            uint sent = SendInput((uint)packets.Length, packets, Marshal.SizeOf<KeyboardInputPacket>());
            return new InputSubmission(sent, Marshal.GetLastWin32Error());
        }, audit.Record);
    }
    internal static ISelectedAttackSession Begin(int pid, ushort key, double repeatSeconds, KiteMovement movement)
    {
        var target = Target.Capture(pid);
        var audit = new Audit(Path.Combine(AppContext.BaseDirectory, "logs"));
        try
        {
            audit.Record("selected-attack-armed", new { pid, target.Path, birthUtc = DateTime.FromFileTimeUtc(target.Birth),
                gameSHA256 = Profile.GameHash, mechanism = "Visible foreground attack-key repeat, max 30 seconds; F8 stop", targetMonsterVerified = false,
                attackVirtualKey = key, intervalSeconds = repeatSeconds, durationSeconds = 30, preparationSeconds = 5,
                movementPlan = movement,
                targetDeathDetection = false, memoryWritten = false, targetExecutedByTool = false });
            return new ForegroundAttackSession(target, audit);
        }
        catch { audit.Dispose(); throw; }
    }
    public bool StopRequested() => (GetAsyncKeyState(0x77) & 0x8000) != 0;
    public bool IsForeground()
    {
        var window = GetForegroundWindow();
        return window != IntPtr.Zero && GetWindowThreadProcessId(window, out uint pid) != 0 && pid == (uint)target.Pid;
    }
    public void SendAttackOnce(ushort key)
    {
        if (faulted || !AttackKeys.Supported(key)) throw new InvalidOperationException("上次输入未确认成功或按键不支持；禁止继续。");
        faulted = true;
        target.Check();
        uint scan = MapVirtualKey(key, 0);
        if (scan == 0 || scan > 0xFF) throw new InvalidOperationException("该按键没有可用的普通扫描码。");
        if (!IsForeground()) throw new InvalidOperationException("游戏焦点或进程身份变化，未发送。");
        keys.Press((ushort)scan);
        faulted = false;
    }
    public void HoldMovement(ushort key)
    {
        target.Check();
        if (!AttackKeys.Supported(key)) throw new InvalidOperationException("未支持的移动键。");
        uint scan = MapVirtualKey(key, 0);
        if (scan == 0 || scan > 0xFF || !IsForeground()) throw new InvalidOperationException("移动键映射或游戏焦点变化。");
        movementScan = (ushort)scan; keys.Hold(movementScan.Value);
    }
    public void ReleaseMovement()
    {
        if (!movementScan.HasValue) return;
        keys.Release(movementScan.Value); movementScan = null;
    }
    internal static KeyboardInputPacket[] BuildInputs(ushort scan) =>
        [new() { Type = 1, Data = new() { Keyboard = new() { Scan = scan, Flags = 0x8 } } },
         new() { Type = 1, Data = new() { Keyboard = new() { Scan = scan, Flags = 0xA } } }];
    public void Dispose() { keys.ReleaseAll(); audit.Dispose(); }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KeyboardInputPacket { internal uint Type; internal InputUnion Data; }
    [StructLayout(LayoutKind.Explicit)]
    internal struct InputUnion
    {
        [FieldOffset(0)] internal KeyboardData Keyboard;
        [FieldOffset(0)] internal MouseData Mouse;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct KeyboardData { internal ushort VirtualKey, Scan; internal uint Flags, Time; internal UIntPtr Extra; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct MouseData { internal int X, Y; internal uint MouseDataValue, Flags, Time; internal UIntPtr Extra; }
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll")] private static extern uint MapVirtualKey(uint code, uint type);
    [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int key);
    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint count, KeyboardInputPacket[] inputs, int size);
}

