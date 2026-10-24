using System.Diagnostics;
using System.Numerics;
using System.Text.Json;
using ImGuiNET;
using Veldrid;
using Veldrid.StartupUtilities;
using Legacy = AttackSpeedLab.Program;

namespace AionLab;

internal static class Desktop
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 2 && args[0] == "--self-test")
            {
                AttackSpeedLab.SelfTest.Run(args[1] + ".core.json");
                ControllerTests.Run(args[1]);
                MovementTests.Run(args[1] + ".movement.json");
                SpeedLockTests.Run(args[1] + ".locks.json");
                AttackBaselineTests.Run(args[1] + ".weapon.json");
                SelectedTargetAttackTests.Run(args[1] + ".combat.json");
                EntityReaderTests.Run(args[1] + ".entities.json");
                TargetHealthTests.Run(args[1] + ".health.json");
                ActionObservationTests.Run(args[1] + ".action.json");
                return 0;
            }
            if (args.Length == 2 && args[0] == "--discover")
            {
                File.WriteAllText(args[1], JsonSerializer.Serialize(new { targets = Legacy.DiscoverTargets(), memoryWritten = false }));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--inspect")
            {
                File.WriteAllText(args[2], Legacy.Inspect(int.Parse(args[1])));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--inspect-movement")
            {
                File.WriteAllText(args[2], JsonSerializer.Serialize(MovementReader.Capture(int.Parse(args[1])),
                    new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--inspect-attack-baseline")
            {
                File.WriteAllText(args[2], JsonSerializer.Serialize(AttackReader.Capture(int.Parse(args[1])),
                    new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--inspect-entities")
            {
                File.WriteAllText(args[2], JsonSerializer.Serialize(EntityReader.Capture(int.Parse(args[1])),
                    new JsonSerializerOptions { WriteIndented = true, IncludeFields = true }));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--inspect-target-health")
            {
                File.WriteAllText(args[2], JsonSerializer.Serialize(TargetHealthReader.Capture(int.Parse(args[1])),
                    new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--replay-health")
            {
                TargetHealthTests.Replay(args[1], args[2]);
                return 0;
            }
            if (args.Length == 5 && args[0] == "--observe-target-health")
            {
                int seconds = int.Parse(args[2]);
                if (seconds is < 1 or > 60) throw new ArgumentOutOfRangeException(nameof(seconds), "观察范围1至60秒。");
                var messages = new List<string>();
                using var health = new HealthObservationController(messages.Add);
                health.Start(int.Parse(args[1]), Path.GetFullPath(args[3]));
                var duration = Stopwatch.StartNew();
                while (health.Active && duration.Elapsed.TotalSeconds < seconds) { health.Tick(); Thread.Sleep(50); }
                if (health.Active) health.Stop("命令行观察时限结束");
                File.WriteAllText(args[4], JsonSerializer.Serialize(new { latest = health.Latest, stop = health.Latch.Assessment,
                    active = health.Active, messages, gameWrites = 0, automaticInputs = 0 }, new JsonSerializerOptions { WriteIndented = true }));
                return health.Latest.Value == null ? 1 : 0;
            }
            bool offline = args.SequenceEqual(new[] { "--offline" });
            bool renderControls = args.Length == 2 && args[0] == "--render-lock-test";
            string renderTest = args.Length == 2 && (args[0] == "--render-test" || renderControls) ? Path.GetFullPath(args[1]) : null;
            if (args.Length != 0 && !offline && renderTest == null) return 2;
            // Renderer fixtures have no game access and must not conflict with the user's live window.
            string mutexName = renderTest == null ? @"Local\REA-AionTW-AttackSpeedLab-Visible" : @"Local\REA-ImGui-Render-" + Guid.NewGuid().ToString("N");
            using var mutex = new Mutex(true, mutexName, out bool created);
            if (!created) return 1;
            try { Run(offline || renderTest != null, renderTest, renderControls); }
            finally { mutex.ReleaseMutex(); }
            return 0;
        }
        catch (Exception e)
        {
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "last-command-error.txt"), e.ToString());
            return 1;
        }
    }

    private static unsafe void Run(bool offline, string renderTest, bool renderControls)
    {
        var window = VeldridStartup.CreateWindow(new WindowCreateInfo(100, 100, 1180, 800,
            WindowState.Normal, "属性实验台 | ImGui"));
        try
        {
            using var device = VeldridStartup.CreateGraphicsDevice(window,
                new GraphicsDeviceOptions(false, null, true), GraphicsBackend.Direct3D11);
            using var commands = device.ResourceFactory.CreateCommandList();
            using var renderer = new ImGuiRenderer(device, device.MainSwapchain.Framebuffer.OutputDescription,
                window.Width, window.Height);
            using var probeTexture = renderTest == null ? null : device.ResourceFactory.CreateTexture(
                TextureDescription.Texture2D((uint)window.Width, (uint)window.Height, 1, 1,
                    device.MainSwapchain.Framebuffer.ColorTargets[0].Target.Format, TextureUsage.RenderTarget));
            using var probeFramebuffer = probeTexture == null ? null :
                device.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, probeTexture));
            var io = ImGui.GetIO();
            io.ConfigFlags |= ImGuiConfigFlags.NavEnableKeyboard;
            io.NativePtr->IniFilename = null;
            var font = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Fonts), "msyh.ttc");
            if (!File.Exists(font)) throw new FileNotFoundException("缺少 Windows 中文字体 Microsoft YaHei。", font);
            io.Fonts.Clear();
            io.Fonts.AddFontFromFileTTF(font, 19, default, io.Fonts.GetGlyphRangesChineseFull());
            renderer.RecreateFontDeviceTexture();
            Theme();
            window.Resized += () =>
            {
                if (window.Width <= 0 || window.Height <= 0) return;
                device.MainSwapchain.Resize((uint)window.Width, (uint)window.Height);
                renderer.WindowResized(window.Width, window.Height);
            };
            using var controller = new LabController();
            var probe = renderTest == null ? null : new RenderProbe(renderTest, renderControls);
            using var locks = new SpeedLocks(controller.Log, renderControls ? probe.BeginFixture : null);
            using var combat = new SelectedAttackController(controller.Log);
            using var health = new HealthObservationController(controller.Log);
            var ui = new LabView(controller, locks, combat, offline && !renderControls, renderControls ? 1 : null,
                renderTest != null ? EntityReaderTests.UiFixture() : null, health,
                renderTest != null ? TargetHealthTests.UiFixture() : null);
            var clock = Stopwatch.StartNew();
            double previous = clock.Elapsed.TotalSeconds, nextPoll = 0;
            while (window.Exists)
            {
                combat.Tick();
                health.Tick();
                var input = window.PumpEvents();
                if (!window.Exists) break;
                if (probe != null) input = probe.Input(ui);
                double now = clock.Elapsed.TotalSeconds;
                if (now >= nextPoll) { controller.Tick(); locks.Tick(); nextPoll = now + .5; }
                renderer.Update((float)Math.Clamp(now - previous, .001, .1), input);
                previous = now;
                ui.Draw(window.Width, window.Height);
                commands.Begin();
                commands.SetFramebuffer(probeFramebuffer ?? device.MainSwapchain.Framebuffer);
                commands.ClearColorTarget(0, new RgbaFloat(.04f, .06f, .09f, 1));
                renderer.Render(device, commands);
                commands.End();
                device.SubmitCommands(commands);
                if (probe != null && probe.AfterDraw(device, probeTexture, ui, controller))
                {
                    window.Close();
                    break;
                }
                device.SwapBuffers(device.MainSwapchain);
                // Bound idle rendering even on drivers/remote desktops ignoring vsync.
                double delay = 1d / 60 - (clock.Elapsed.TotalSeconds - now);
                if (delay > .001) Thread.Sleep((int)(delay * 1000));
            }
            device.WaitForIdle();
        }
        finally { if (window.Exists) window.Close(); }
    }

    private static void Theme()
    {
        ImGui.StyleColorsDark();
        var s = ImGui.GetStyle();
        s.WindowPadding = new Vector2(22, 18);
        s.FramePadding = new Vector2(12, 8);
        s.ItemSpacing = new Vector2(12, 12);
        s.FrameRounding = 5; s.ChildRounding = 8; s.WindowRounding = 0;
        s.Colors[(int)ImGuiCol.WindowBg] = new Vector4(.045f, .065f, .095f, 1);
        s.Colors[(int)ImGuiCol.ChildBg] = new Vector4(.07f, .095f, .13f, 1);
        s.Colors[(int)ImGuiCol.Button] = new Vector4(.08f, .28f, .35f, 1);
        s.Colors[(int)ImGuiCol.ButtonHovered] = new Vector4(.1f, .42f, .5f, 1);
        s.Colors[(int)ImGuiCol.Header] = new Vector4(.08f, .3f, .38f, 1);
        s.Colors[(int)ImGuiCol.Text] = new Vector4(.88f, .92f, .96f, 1);
    }
}

internal sealed class LabView(LabController controller, SpeedLocks locks, SelectedAttackController combat, bool offline,
    int? fixturePid = null, Observation<EntitySnapshot> entityFixture = null,
    HealthObservationController health = null, Observation<TargetHealthSnapshot> healthFixture = null)
{
    private Observation<AttackSnapshot> attack = AttackReader.Pending();
    private Observation<MovementSnapshot> movement = new PendingMovement().Read();
    private Observation<EntitySnapshot> entities = entityFixture ?? EntityReader.Pending();
    private readonly string[] pages = ["攻速实验", "移动速度", "实体观察", "证据与接入"];
    private List<int> targets = [];
    private int selected = -1, desired = 700, page;
    private float movementDraft = 7.8f;
    private int intervalReduction = 25;
    private bool percentMode = true, previousAttackActive;
    private int combatKey = Array.FindIndex(AttackKeys.Choices, k => k.VirtualKey == 0x31);
    private float combatInterval = 2.5f, movementStep = 1f;
    private bool useStrafe = true;
    private string filter = "";
    private bool initialized;
    internal int SelectedPage => page;
    internal bool HasActiveSpeedSession => locks.Any;
    internal bool HasActiveCombatSession => combat.Active || combat.CleanupPending;
    internal bool HasActiveHealthObservation => health?.Active == true;
    internal bool IsSpeedLocked(SpeedKind kind) => locks.Locked(kind);
    internal Vector2[] LockCenters { get; } = new Vector2[2];
    internal Vector2[] NavigationCenters { get; } = new Vector2[4];
    private static readonly Vector4 Accent = new(.27f, .81f, .85f, 1);
    private static readonly Vector4 Muted = new(.58f, .67f, .75f, 1);

    // User text and percentages are data, never native printf format strings.
    private static void Wrapped(string text)
    {
        ImGui.PushTextWrapPos(0);
        ImGui.TextUnformatted(text);
        ImGui.PopTextWrapPos();
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception e) { controller.Log("操作未完成：" + e.Message); }
    }
    private void Refresh()
    {
        if (health?.Active == true) health.Stop("刷新进程，结束旧目标观察");
        targets = fixturePid.HasValue ? [fixturePid.Value] : offline ? [] : Legacy.DiscoverTargets();
        selected = targets.Count > 0 ? 0 : -1;
        movement = new PendingMovement().Read();
        attack = fixturePid.HasValue ? AttackReader.Fixture(2400) : AttackReader.Pending();
        entities = entityFixture ?? EntityReader.Pending();
        controller.Log(offline ? "离线预览：未枚举游戏进程。" : $"找到 {targets.Count} 个符合既有路径的目标。");
    }
    private void SelectProcess(int index)
    {
        if (health?.Active == true) health.Stop("切换观察进程");
        selected = index; entities = EntityReader.Pending(); attack = AttackReader.Pending(); movement = new PendingMovement().Read();
    }
    public void Draw(int width, int height)
    {
        if (!initialized) { Guard(Refresh); initialized = true; }
        if (previousAttackActive && !locks.Active(SpeedKind.Attack)) InvalidateAttack();
        ImGui.SetNextWindowPos(Vector2.Zero);
        ImGui.SetNextWindowSize(new Vector2(width, height));
        ImGui.Begin("属性实验台", ImGuiWindowFlags.NoDecoration | ImGuiWindowFlags.NoMove |
            ImGuiWindowFlags.NoSavedSettings);
        ImGui.TextColored(Accent, "属性实验台  /  SPEED LAB");
        ImGui.SameLine(); ImGui.TextDisabled("IMGUI · 2026.10");
        ImGui.TextColored(Muted, fixturePid.HasValue ? "离线交互夹具 · 仅模拟会话，不连接游戏" : offline ? "离线界面预览 · 未连接游戏" : "窗口内按需连接 · 操作与还原结果见下方记录");
        if (locks.Any || combat.Active || combat.CleanupPending || health?.Active == true)
        {
            if (locks.Any) Wrapped(locks.Summary);
            if (combat.Active || combat.CleanupPending) Wrapped(combat.Status);
            if (health?.Active == true) Wrapped($"当前目标只读观察，剩余 {Math.Ceiling(health.Remaining)} 秒。");
            if (ImGui.Button("全部停止并还原"))
            { combat.Cancel("手动停止按键"); locks.StopAll("手动全部停止"); if (health?.Active == true) health.Stop("手动全部停止"); InvalidateAttack(); }
        }
        if (controller.Active)
        {
            ImGui.ProgressBar((float)(controller.Remaining / 60), new Vector2(-1, 8), "");
            ImGui.Text($"剩余 {Math.Ceiling(controller.Remaining)} 秒");
            ImGui.SameLine();
            if (ImGui.Button("立即停止并还原")) controller.Stop("手动停止");
        }
        ImGui.Separator();
        float bodyHeight = Math.Max(180, ImGui.GetContentRegionAvail().Y - 180);
        ImGui.BeginChild("navigation", new Vector2(165, bodyHeight), true);
        ImGui.TextDisabled("工作区");
        for (int i = 0; i < pages.Length; i++)
        {
            if (ImGui.Selectable(pages[i], page == i, ImGuiSelectableFlags.None, new Vector2(0, 38))) page = i;
            NavigationCenters[i] = (ImGui.GetItemRectMin() + ImGui.GetItemRectMax()) / 2;
        }
        ImGui.Spacing(); Wrapped("攻速 / 移速\n独立勾选维护\n实体与目标只读\n自动战斗：待验证");
        ImGui.EndChild();
        ImGui.SameLine();
        ImGui.BeginChild("content", new Vector2(0, bodyHeight), true);
        switch (page)
        {
            case 0: Attack(); break;
            case 1: Movement(); break;
            case 2: EntityObservationPanel(); break;
            case 3: EvidencePage(); break;
        }
        ImGui.EndChild();
        ImGui.TextColored(Accent, "操作记录");
        ImGui.SameLine(); ImGui.TextDisabled("保留最近 200 条 · 事务原始日志见 logs/");
        ImGui.BeginChild("log", new Vector2(0, 0), true);
        foreach (var message in controller.Messages) Wrapped(message);
        ImGui.EndChild();
        ImGui.End();
        previousAttackActive = locks.Active(SpeedKind.Attack);
    }
    private void InvalidateAttack() => attack = new(Availability.Stale, "旧会话已结束；换武器或重新开启前，请采集当前基线。", attack.Value);
    private bool AttackReady => attack.State == Availability.Ready && attack.Value?.State.Consistent == true;
    private void StartAttack(bool maintain)
    {
        try { locks.Start(targets[selected], SpeedKind.Attack, desired, maintain, attack.Value.Binding); }
        catch { InvalidateAttack(); throw; }
    }
    private void Attack()
    {
        ImGui.TextColored(Accent, "01  攻速实验");
        Wrapped("按当前武器基线缩短间隔；换武器先停止并重新采集。不是已验证的服务器攻击频率。");
        ImGui.BeginDisabled(locks.Any || offline);
        ImGui.SetNextItemWidth(270);
        if (ImGui.BeginCombo("目标进程", selected >= 0 ? $"aion.bin · PID {targets[selected]}" : "未选择目标"))
        {
            for (int i = 0; i < targets.Count; i++)
                if (ImGui.Selectable($"aion.bin · PID {targets[i]}", selected == i)) SelectProcess(i);
            ImGui.EndCombo();
        }
        if (ImGui.Button("刷新目标")) Guard(Refresh);
        ImGui.EndDisabled();
        ImGui.SameLine();
        ImGui.BeginDisabled(selected < 0 || fixturePid.HasValue || offline || locks.Active(SpeedKind.Attack));
        if (ImGui.Button("采集当前武器基线")) Guard(() =>
        {
            attack = AttackReader.Capture(targets[selected]);
            controller.Log(JsonSerializer.Serialize(attack));
        });
        ImGui.EndDisabled();
        uint baseline = attack.Value?.Binding.Interval ?? 0;
        intervalReduction = Math.Clamp(intervalReduction, 0, 65);
        if (AttackReady && percentMode && !locks.Active(SpeedKind.Attack)) desired = AttackRules.IntervalForPercent(baseline, intervalReduction);
        if (AttackReady && !percentMode && !locks.Active(SpeedKind.Attack)) desired = Math.Clamp(desired, 400, (int)baseline);
        if (attack.Value is { } sample)
            Wrapped($"上次采样 I={sample.State.Interval} / 镜像={sample.State.Mirror} / U={sample.State.U} / V={sample.State.V} / 系数={sample.State.Scale}");
        if (!AttackReady) Wrapped(attack.Reason);
        Wrapped(AttackReady ? $"目标间隔 {desired}；相对采样基线缩短 {100d * (baseline - (double)desired) / baseline:0.##}%（工具下限400）" : "基线尚未确认；不计算目标比例，不允许开始攻速修改。");
        LockControl(SpeedKind.Attack, desired, "勾选锁定攻速");
        ImGui.SameLine();
        ImGui.BeginDisabled(locks.Active(SpeedKind.Attack) || offline || selected < 0 || !AttackReady);
        if (ImGui.Button("60秒实验")) Guard(() => StartAttack(false));
        ImGui.EndDisabled();
        ImGui.Separator();
        ImGui.BeginDisabled(locks.Active(SpeedKind.Attack) || offline || !AttackReady);
        ImGui.Checkbox("按基线百分比设置", ref percentMode);
        if (percentMode)
        {
            ImGui.SetNextItemWidth(270);
            if (ImGui.BeginCombo("间隔缩短档位", intervalReduction + "%"))
            {
                foreach (int preset in SpeedSettings.AttackReductionPresets)
                    if (ImGui.Selectable(preset + "%", intervalReduction == preset)) intervalReduction = preset;
                ImGui.EndCombo();
            }
            ImGui.SetNextItemWidth(270);
            ImGui.SliderInt("间隔缩短百分比", ref intervalReduction, 0, 65);
        }
        else
        {
            desired = Math.Clamp(desired, 400, (int)Math.Max(400, baseline));
            ImGui.SetNextItemWidth(270);
            ImGui.SliderInt("绝对目标间隔", ref desired, 400, (int)Math.Max(400, baseline));
        }
        ImGui.EndDisabled();
        ImGui.Spacing();
        Wrapped("开始前停止攻击，取消攻速增益。需要I/镜像/U/V一致、系数1；一致不能证明没有增益。采集绑定进程和角色，开始时再次校验。更快档位尚待游戏验证。");
        ImGui.TextColored(Muted, "限时：一次应用 / 60秒；勾选：持续检查维护 / 取消还原");
        Wrapped("正常关闭会尝试还原。强制结束、断电或角色重建时，无法保证恢复旧对象。");
    }
    private void Movement()
    {
        ImGui.TextColored(Accent, "02  移动速度");
        Wrapped("正常30%卷轴已观察 6 -> 7.8 -> 6。采集五字段；本地修改的实际位移仍待验证。");
        ImGui.BeginDisabled(locks.Any || offline);
        ImGui.SetNextItemWidth(270);
        if (ImGui.BeginCombo("移速目标", selected >= 0 ? $"aion.bin · PID {targets[selected]}" : "未选择目标"))
        {
            for (int i = 0; i < targets.Count; i++)
                if (ImGui.Selectable($"aion.bin · PID {targets[i]}", selected == i)) SelectProcess(i);
            ImGui.EndCombo();
        }
        if (ImGui.Button("刷新移速目标")) Guard(Refresh);
        ImGui.SameLine();
        ImGui.BeginDisabled(selected < 0 || fixturePid.HasValue);
        if (ImGui.Button("只读采集移速")) Guard(() =>
        {
            movement = MovementReader.Capture(targets[selected]);
            controller.Log(JsonSerializer.Serialize(movement));
        });
        ImGui.EndDisabled();
        ImGui.EndDisabled();
        Wrapped($"采样状态：{movement.State} · {movement.Reason}");
        if (movement.Value is { } snapshot && ImGui.CollapsingHeader("上次移速快照（展开查看五字段）"))
        {
            Wrapped($"PID {snapshot.Pid} · B={snapshot.ModuleBase} · C={snapshot.Character}");
            Wrapped($"采样时间 {snapshot.Evidence.CapturedAt:O}；{snapshot.Unit}。仅显示上次采样，不自动刷新。");
            if (ImGui.BeginTable("movement-fields", 4, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
            {
                foreach (var name in new[] { "字段", "地址", "值 / 错误", "float32位表示" }) ImGui.TableSetupColumn(name);
                ImGui.TableHeadersRow();
                foreach (var field in snapshot.Fields)
                {
                    ImGui.TableNextRow(); ImGui.TableSetColumnIndex(0); Wrapped(field.Relative);
                    ImGui.TableSetColumnIndex(1); Wrapped(field.Address);
                    ImGui.TableSetColumnIndex(2); Wrapped(field.Value?.ToString("R") ?? field.Error ?? "未知");
                    ImGui.TableSetColumnIndex(3); Wrapped(field.Bits ?? "未知");
                }
                ImGui.EndTable();
            }
        }
        ImGui.Separator();
        ImGui.BeginDisabled(locks.Active(SpeedKind.Movement) || offline);
        ImGui.SetNextItemWidth(270);
        if (ImGui.BeginCombo("移速档位", movementDraft.ToString("0.##")))
        {
            foreach (float preset in SpeedSettings.MovementPresets)
                if (ImGui.Selectable(preset.ToString("0.##"), movementDraft == preset)) movementDraft = preset;
            ImGui.EndCombo();
        }
        ImGui.SetNextItemWidth(270);
        ImGui.SliderFloat("目标移速标度", ref movementDraft, 6f, 15f, "%.2f");
        ImGui.BeginDisabled(selected < 0);
        if (ImGui.Button("开始60秒移速实验")) Guard(() => locks.Start(targets[selected], SpeedKind.Movement, movementDraft, false));
        ImGui.EndDisabled();
        ImGui.EndDisabled();
        LockControl(SpeedKind.Movement, movementDraft, "勾选锁定移速");
        ImGui.Spacing();
        Wrapped("准备：原装备、无增益、6.0基线、安全路面且静止。联动速度两处、平方、倒数和镜像；不调用通知函数，不等同服务器卷轴。");
        Wrapped("限时模式遇外部覆盖即停止；勾选模式每500ms检查并补写。大于7.8的新档位未验证。维护时勿换装备/增益；取消后再调整档位。强制结束/断电不能保证还原。");
    }
    private void LockControl(SpeedKind kind, float value, string label)
    {
        bool locked = locks.Locked(kind);
        ImGui.BeginDisabled(offline || selected < 0 || (locks.Active(kind) && !locked) || (kind == SpeedKind.Attack && !AttackReady && !locked));
        if (ImGui.Checkbox(label, ref locked)) Guard(() =>
        {
            if (locked)
            {
                if (kind == SpeedKind.Attack) StartAttack(true);
                else locks.Start(targets[selected], kind, value, true);
            }
            else { locks.Stop(kind, "取消勾选"); if (kind == SpeedKind.Attack) InvalidateAttack(); }
        });
        LockCenters[(int)kind] = (ImGui.GetItemRectMin() + ImGui.GetItemRectMax()) / 2;
        ImGui.EndDisabled();
        if (locks.Active(kind))
        {
            ImGui.SameLine();
            if (ImGui.Button("停止此项##" + kind)) { locks.Stop(kind, "停止此项"); if (kind == SpeedKind.Attack) InvalidateAttack(); }
        }
    }
    private void EntityObservationPanel()
    {
        ImGui.TextColored(Accent, "03  实体与当前目标 · 只读观察");
        Wrapped("按模块基址和实体树读取；生命是客户端指示，死亡判定已有REA及实测证据，敌我与可攻击性仍未知。");
        TargetHealthPanel();
        ImGui.BeginDisabled(offline || fixturePid.HasValue);
        ImGui.SetNextItemWidth(230);
        if (ImGui.BeginCombo("观察进程", selected >= 0 ? $"PID {targets[selected]}" : "未选择"))
        {
            for (int i = 0; i < targets.Count; i++)
                if (ImGui.Selectable($"PID {targets[i]}", selected == i))
                    SelectProcess(i);
            ImGui.EndCombo();
        }
        if (ImGui.Button("刷新进程##entities")) Guard(Refresh);
        ImGui.SameLine(); ImGui.BeginDisabled(selected < 0);
        if (ImGui.Button("采集周围实体（只读）")) Guard(() =>
        {
            entities = EntityReader.Capture(targets[selected]);
            string directory = Path.Combine(AppContext.BaseDirectory, "logs"); Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, $"entities-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}.json");
            File.WriteAllText(path, JsonSerializer.Serialize(entities, new JsonSerializerOptions { WriteIndented = true, IncludeFields = true }));
            controller.Log("实体只读采样：" + entities.Reason + " 日志：" + path);
        });
        ImGui.EndDisabled(); ImGui.EndDisabled();
        Wrapped(entities.Reason);
        var snapshot = entities.Value;
        if (snapshot != null)
        {
            Wrapped($"PID {snapshot.Pid} · 基址 {snapshot.ModuleBase} · 角色 {snapshot.LocalCharacter} · 节点 {snapshot.VisitedNodes} · 角色类候选 {snapshot.Candidates.Length}");
            Wrapped($"目标句柄 {snapshot.TargetHandleBefore} → {snapshot.TargetHandleAfter?.ToString() ?? "未知"} · 采样于 {snapshot.Evidence.CapturedAt.ToLocalTime():HH:mm:ss}；这是静态快照，点击重新采集才刷新。");
            if (snapshot.Issues.Length != 0) Wrapped(string.Join("；", snapshot.Issues));
        }
        ImGui.SetNextItemWidth(270);
        ImGui.InputText("名称筛选", ref filter, 128);
        if (ImGui.BeginTable("entities", 6, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY,
            new Vector2(0, 240)))
        {
            foreach (var name in new[] { "名称候选", "句柄 / 标记", "距离候选", "对象地址", "类型码 / 状态", "血量 / 敌我" }) ImGui.TableSetupColumn(name);
            ImGui.TableHeadersRow();
            if (snapshot == null) { ImGui.TableNextRow(); ImGui.TableSetColumnIndex(0); ImGui.TextDisabled("尚未采集"); }
            else foreach (var row in snapshot.Candidates.Where(x => string.IsNullOrEmpty(filter) ||
                (x.NameCandidate?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)))
            {
                ImGui.TableNextRow(); ImGui.TableSetColumnIndex(0); ImGui.TextUnformatted(row.NameCandidate ?? "未知");
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted($"{row.Handle} {(row.Local ? "自己" : row.TargetHandleMatch ? "目标候选" : "")}");
                ImGui.TableSetColumnIndex(2); ImGui.TextUnformatted(row.DistanceCandidate?.ToString("F2") ?? "未知");
                ImGui.TableSetColumnIndex(3); ImGui.TextUnformatted(row.CharacterAddress);
                ImGui.TableSetColumnIndex(4); ImGui.TextUnformatted($"{row.TypeCode?.ToString() ?? "未知"} / {(row.BindingMatched && row.Errors.Length == 0 ? "已读" : "不完整")}");
                ImGui.TableSetColumnIndex(5); ImGui.TextUnformatted(
                    $"{(row.HealthFraction.HasValue ? (row.HealthFraction.Value * 100).ToString("F0") + "%" : "未知")} / {(row.Alive == false ? "客户端死亡" : "敌我未知")}");
                if (row.Errors.Length != 0 && ImGui.IsItemHovered())
                { ImGui.BeginTooltip(); ImGui.TextUnformatted(string.Join("；", row.Errors)); ImGui.EndTooltip(); }
            }
            ImGui.EndTable();
        }
        Wrapped("当前页只读；普通攻击调用的参数、线程及实际停手效果仍待验证。");
    }
    private void TargetHealthPanel()
    {
        if (health == null) return;
        ImGui.BeginDisabled(offline || fixturePid.HasValue || selected < 0 || health.Active);
        if (ImGui.Button("读取目标生命")) Guard(() => health.Sample(targets[selected]));
        ImGui.SameLine();
        if (ImGui.Button("观察当前目标60秒")) Guard(() => health.Start(targets[selected], Path.Combine(AppContext.BaseDirectory, "logs")));
        ImGui.EndDisabled();
        if (health.Active)
        {
            ImGui.SameLine();
            if (ImGui.Button("停止观察")) health.Stop("用户手动停止观察");
        }
        var observation = healthFixture ?? health.Latest; var s = observation.Value;
        Wrapped(observation.Reason);
        if (s != null)
        {
            string percentage = s.Stable && s.Life?.HealthFraction is float f ? (f * 100).ToString("F0") + "%" : "未知";
            string death = s.Stable && s.Life?.ClientDead.HasValue == true ? s.Life.ClientDead.Value ? "是" : "否（可攻击性未知）" : "未知";
            Wrapped($"当前目标：{s.Name ?? "未知"} · 句柄 {s.SelectedBefore} → {s.SelectedAfter?.ToString() ?? "未知"} · 生命指示 {percentage} · 客户端死亡 {death}");
            Wrapped($"对象ID {s.Binding?.Identifier.ToString() ?? "未知"} · 样本 {s.Evidence.CapturedAt.ToLocalTime():HH:mm:ss.fff} · {(s.Stable ? "绑定与字段两读一致" : "不完整/不稳定")}（顺序采样）");
            if (s.Issues.Length > 0) Wrapped(string.Join("；", s.Issues));
            var decision = TargetStopLatch.Evaluate(observation, s.Binding, DateTimeOffset.UtcNow);
            if (decision.StopRequired) Wrapped("此快照要求停止：" + string.Join("；", decision.Reasons));
            if (ImGui.CollapsingHeader("生命原始字段 / 证据"))
            {
                foreach (var field in s.Life?.Fields ?? []) Wrapped($"{field.Relative}：{field.First?.ToString() ?? "未知"} → {field.Confirm?.ToString() ?? "未知"} {field.Error}");
                Wrapped(s.Evidence.Source);
            }
            if (ImGui.CollapsingHeader("本地角色动作 / 攻击调用链观察"))
            {
                var action = s.LocalAction;
                Wrapped(action == null ? "此旧日志未包含动作字段。" :
                    $"动作值 {action.GoalKind?.ToString() ?? "未知"} · 阶段 {action.GoalPhase?.ToString() ?? "未知"} · {(s.IdentityMatched ? action.GoalBranch : "角色绑定未确认")}");
                Wrapped("请求计数不是命中数；传输待发字节包含所有业务，不能当作待发攻击数量。此区只读。");
                foreach (var field in action?.Fields ?? [])
                    Wrapped($"{field.Name} ({field.Relative})：{field.First?.ToString() ?? "未知"} → {field.Confirm?.ToString() ?? "未知"} {field.Error}");
                if (action != null) Wrapped(action.Source);
            }
        }
        Wrapped(health.Active ? $"只读观察中，剩余 {Math.Ceiling(health.Remaining)} 秒；尚未触发停止条件（不代表可攻击）。" :
            "停止状态：" + string.Join("；", health.Latch.Assessment.Reasons));
        Wrapped("死亡、生命归零、清空/切换目标、身份变化或读失败即结束观察并锁存原因；必须手动重新开始。本功能不发送攻击。");
        ImGui.Separator();
    }
    private void SelectedTargetCombat()
    {
        ImGui.TextColored(Accent, "03  当前目标攻击与横移 · 30秒观察测试");
        Wrapped("手动选中怪物后启动；用户已确认1是攻击、A/D横移且移动中能出箭。仅普通前台按键，不修改游戏内存。");
        Wrapped(combat.Status);
        if (combat.Active)
        {
            Wrapped($"{(combat.Preparing ? "准备" : "运行")}剩余 {Math.Ceiling(combat.Remaining)} 秒；攻击键已发送 {combat.SentCount} 次。");
            if (ImGui.Button("停止按键并释放方向键")) combat.Cancel("手动停止，取消后续按键。");
        }
        if (combat.CleanupPending && ImGui.Button("重试释放残留方向键")) combat.RetryCleanup();
        ImGui.BeginDisabled(offline || fixturePid.HasValue || combat.Active || combat.CleanupPending || locks.Any);
        ImGui.SetNextItemWidth(230);
        if (ImGui.BeginCombo("按键目标进程", selected >= 0 ? $"PID {targets[selected]}" : "未选择"))
        {
            for (int i = 0; i < targets.Count; i++)
                if (ImGui.Selectable($"PID {targets[i]}", selected == i)) SelectProcess(i);
            ImGui.EndCombo();
        }
        if (ImGui.Button("刷新按键目标")) Guard(Refresh);
        ImGui.SetNextItemWidth(230);
        if (ImGui.BeginCombo("攻击单键", AttackKeys.Choices[combatKey].Name))
        {
            for (int i = 0; i < AttackKeys.Choices.Length; i++)
                if (ImGui.Selectable(AttackKeys.Choices[i].Name, combatKey == i)) combatKey = i;
            ImGui.EndCombo();
        }
        ImGui.SetNextItemWidth(230); ImGui.SliderFloat("按攻击键的间隔（秒）", ref combatInterval, .5f, 10f, "%.2f");
        ImGui.Checkbox("交替横移 A / D", ref useStrafe);
        ImGui.SetNextItemWidth(230); ImGui.SliderFloat("每向横移时间（秒）", ref movementStep, .25f, 2f, "%.2f");
        ImGui.BeginDisabled(selected < 0);
        if (ImGui.Button("准备5秒后开始30秒测试")) Guard(() => combat.Arm(targets[selected], AttackKeys.Choices[combatKey].VirtualKey,
            combatInterval, useStrafe ? new(0x41, 0x44, movementStep) : null));
        ImGui.EndDisabled(); ImGui.EndDisabled();
        Wrapped("开始后5秒内切回游戏，关闭聊天/菜单，保持原目标。按住F8直到停止，或切离游戏；停止时尝试释放工具按住的方向键。先关闭速度实验再测试。");
        Wrapped("尚未读取目标身份、血量、死亡和距离；目标死亡或角色危险时请手动停止。左右交替不含绕障/导航/保持射程，不能无人值守。系统接受按键也不等于游戏成功攻击。");
        if (ImGui.CollapsingHeader("实体只读快照")) EntityObservationPanel();
    }
    private static void EvidencePage()
    {
        ImGui.TextColored(Accent, "04  证据与接入");
        Wrapped("沿用原工具的版本和动态角色定位；当前新增独立的攻速/移速事务与窗口内维护。REA 提供既有静态字段证据，新锁定档位未完成游戏验证。");
        ImGui.Separator();
        Wrapped("当前配置路径：" + AttackSpeedLab.Profile.GamePath);
        Wrapped("Game.dll SHA256：" + AttackSpeedLab.Profile.GameHash);
        Wrapped("注意：该路径来自旧研究环境。本机找不到目标时显示空列表；本次不修改路径或放宽版本校验。");
        ImGui.Spacing();
        Wrapped("验证层级：本机内存夹具通过 ≠ 游戏效果验证通过。回家后仍需验证角色动画、实际命中间隔、服务器判定和停止后的恢复情况。");
        Wrapped("架构与验收：同目录 architecture.html。离线入口：SpeedLab.exe --offline。工具保持可见，无自启、伪装或反检测。");
    }
}
