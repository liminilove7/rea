using Input = AionLab.ForegroundAttackSession.KeyboardInputPacket;

namespace AionLab;

// Owns only scan codes for which a down event was attempted. Cleanup never sends a fresh down.
internal record InputSubmission(uint Accepted, int Win32Error);
internal sealed class OwnedKeyEmitter(Func<Input[], InputSubmission> send, Action<string, object> audit)
{
    private readonly HashSet<ushort> held = [];
    internal int HeldCount => held.Count;
    internal void Press(ushort scan)
    {
        if (held.Contains(scan)) throw new InvalidOperationException("该按键已有未释放事件。");
        audit("key-press-intent", new { scan });
        held.Add(scan);
        var submission = send(ForegroundAttackSession.BuildInputs(scan)); uint accepted = submission.Accepted;
        if (accepted is 0 or 2) held.Remove(scan);
        audit("key-press-result", new { scan, submission, expected = 2, gameAcknowledged = false });
        if (accepted != 2) throw new IOException($"系统只接受{accepted}/2个攻击按键事件，Win32={submission.Win32Error}，原因未确认；停止，不重发攻击。");
    }
    internal void Hold(ushort scan)
    {
        if (held.Contains(scan)) throw new InvalidOperationException("方向键已经按住。");
        audit("movement-down-intent", new { scan }); held.Add(scan);
        var submission = send([ForegroundAttackSession.BuildInputs(scan)[0]]); uint accepted = submission.Accepted;
        if (accepted == 0) held.Remove(scan);
        audit("movement-down-result", new { scan, submission, gameAcknowledged = false });
        if (accepted != 1) throw new IOException("系统未确认接受方向键按下，停止。Win32=" + submission.Win32Error);
    }
    internal void Release(ushort scan)
    {
        if (!held.Contains(scan)) return;
        // Release even if the audit disk failed; keep ownership if the OS rejects the up event.
        var submission = send([ForegroundAttackSession.BuildInputs(scan)[1]]); uint accepted = submission.Accepted;
        if (accepted == 1) held.Remove(scan);
        audit("key-up-result", new { scan, submission });
        if (accepted != 1) throw new IOException("方向键/部分攻击键尚未释放，需重试释放。Win32=" + submission.Win32Error);
    }
    internal void ReleaseAll()
    {
        var errors = new List<string>();
        foreach (ushort scan in held.ToArray())
            try { Release(scan); } catch (Exception e) { errors.Add(e.Message); }
        if (errors.Count > 0) throw new IOException(string.Join("；", errors));
    }
}
