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
            bool offline = args.SequenceEqual(new[] { "--offline" });
            string renderTest = args.Length == 2 && args[0] == "--render-test" ? Path.GetFullPath(args[1]) : null;
            if (args.Length != 0 && !offline && renderTest == null) return 2;
            using var mutex = new Mutex(true, @"Local\REA-AionTW-AttackSpeedLab-Visible", out bool created);
            if (!created) return 1;
            try { Run(offline || renderTest != null, renderTest); }
            finally { mutex.ReleaseMutex(); }
            return 0;
        }
        catch (Exception e)
        {
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "last-command-error.txt"), e.ToString());
            return 1;
        }
    }

    private static unsafe void Run(bool offline, string renderTest)
    {
        var window = VeldridStartup.CreateWindow(new WindowCreateInfo(100, 100, 1180, 800,
            WindowState.Normal, "AION Research Lab | ImGui"));
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
            var ui = new LabView(controller, offline);
            var probe = renderTest == null ? null : new RenderProbe(renderTest);
            var clock = Stopwatch.StartNew();
            double previous = clock.Elapsed.TotalSeconds, nextPoll = 0;
            while (window.Exists)
            {
                var input = window.PumpEvents();
                if (!window.Exists) break;
                if (probe != null) input = probe.Input(ui);
                double now = clock.Elapsed.TotalSeconds;
                if (now >= nextPoll) { controller.Tick(); nextPoll = now + .5; }
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

internal sealed class LabView(LabController controller, bool offline)
{
    private readonly IMovementSource movement = new PendingMovement();
    private readonly IMonsterSource monsters = new PendingMonsters();
    private readonly string[] pages = ["攻速实验", "移动速度", "怪物识别", "证据与接入"];
    private List<int> targets = [];
    private int selected = -1, desired = 700, page;
    private float movementDraft = 1;
    private string filter = "";
    private bool initialized;
    internal int SelectedPage => page;
    internal Vector2[] NavigationCenters { get; } = new Vector2[4];
    private static readonly Vector4 Accent = new(.27f, .81f, .85f, 1);
    private static readonly Vector4 Muted = new(.58f, .67f, .75f, 1);

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception e) { controller.Log("操作未完成：" + e.Message); }
    }
    private void Refresh()
    {
        targets = offline ? [] : Legacy.DiscoverTargets();
        selected = targets.Count > 0 ? 0 : -1;
        controller.Log(offline ? "离线预览：未枚举游戏进程。" : $"找到 {targets.Count} 个符合既有路径的目标。");
    }
    public void Draw(int width, int height)
    {
        if (!initialized) { Guard(Refresh); initialized = true; }
        ImGui.SetNextWindowPos(Vector2.Zero);
        ImGui.SetNextWindowSize(new Vector2(width, height));
        ImGui.Begin("AION Lab", ImGuiWindowFlags.NoDecoration | ImGuiWindowFlags.NoMove |
            ImGuiWindowFlags.NoSavedSettings);
        ImGui.TextColored(Accent, "AION  /  RESEARCH LAB");
        ImGui.SameLine(); ImGui.TextDisabled("IMGUI · 2026.10");
        ImGui.TextColored(Muted, offline ? "离线界面预览 · 未连接游戏" : controller.Status);
        if (controller.Active)
        {
            ImGui.ProgressBar((float)(controller.Remaining / 60), new Vector2(-1, 8), "");
            ImGui.Text($"剩余 {Math.Ceiling(controller.Remaining)} 秒");
            ImGui.SameLine();
            if (ImGui.Button("立即停止并还原")) controller.Stop("手动停止");
        }
        ImGui.Separator();
        float bodyHeight = Math.Max(180, ImGui.GetContentRegionAvail().Y - 220);
        ImGui.BeginChild("navigation", new Vector2(165, bodyHeight), true);
        ImGui.TextDisabled("工作区");
        for (int i = 0; i < pages.Length; i++)
        {
            if (ImGui.Selectable(pages[i], page == i, ImGuiSelectableFlags.None, new Vector2(0, 38))) page = i;
            NavigationCenters[i] = (ImGui.GetItemRectMin() + ImGui.GetItemRectMax()) / 2;
        }
        ImGui.Spacing(); ImGui.TextWrapped("攻速：已实现\n移速：预留\n怪物：预留");
        ImGui.EndChild();
        ImGui.SameLine();
        ImGui.BeginChild("content", new Vector2(0, bodyHeight), true);
        switch (page)
        {
            case 0: Attack(); break;
            case 1: Movement(); break;
            case 2: Monsters(); break;
            case 3: EvidencePage(); break;
        }
        ImGui.EndChild();
        ImGui.TextColored(Accent, "操作记录");
        ImGui.SameLine(); ImGui.TextDisabled("保留最近 200 条 · 事务原始日志见 logs/");
        ImGui.BeginChild("log", new Vector2(0, 0), true);
        foreach (var message in controller.Messages) ImGui.TextWrapped(message);
        ImGui.EndChild();
        ImGui.End();
    }
    private void Attack()
    {
        ImGui.TextColored(Accent, "01  攻速实验");
        ImGui.TextWrapped("沿用原工具的间隔实验。数值更小代表客户端间隔更短；服务器命中频率仍需实测。");
        ImGui.Separator();
        ImGui.BeginDisabled(controller.Active || offline);
        ImGui.SetNextItemWidth(270);
        if (ImGui.BeginCombo("目标进程", selected >= 0 ? $"aion.bin · PID {targets[selected]}" : "未选择目标"))
        {
            for (int i = 0; i < targets.Count; i++)
                if (ImGui.Selectable($"aion.bin · PID {targets[i]}", selected == i)) selected = i;
            ImGui.EndCombo();
        }
        if (ImGui.Button("刷新目标")) Guard(Refresh);
        ImGui.SameLine();
        ImGui.BeginDisabled(selected < 0);
        if (ImGui.Button("只读检查")) Guard(() => controller.Log(Legacy.Inspect(targets[selected])));
        ImGui.EndDisabled();
        ImGui.SetNextItemWidth(270);
        ImGui.SliderInt("目标间隔", ref desired, 700, 1200);
        ImGui.BeginDisabled(selected < 0 || desired < 700 || desired > 1200);
        if (ImGui.Button("开始 60 秒实验", new Vector2(230, 44)))
            Guard(() => controller.Start(targets[selected], desired));
        ImGui.EndDisabled();
        ImGui.EndDisabled();
        ImGui.Spacing();
        ImGui.TextWrapped("准备条件：原武器、无攻速增益、1200 基线、动画系数 1。进程路径和模块哈希必须符合既有研究配置。");
        ImGui.TextColored(Muted, "只应用一次 · 500 ms 校验 · 最长 60 秒 · 停止时尝试还原");
        ImGui.TextWrapped("正常关闭会尝试还原。强制结束、断电或角色重建时，无法保证恢复旧对象。");
    }
    private void Movement()
    {
        var snapshot = movement.Read();
        ImGui.TextColored(Accent, "02  移动速度");
        ImGui.Text("状态：尚未接入");
        ImGui.TextWrapped(snapshot.Reason);
        ImGui.Separator();
        ImGui.Text("当前速度：未知     单位：未确认");
        ImGui.SetNextItemWidth(270);
        ImGui.SliderFloat("倍率草案", ref movementDraft, .5f, 2, "%.2f");
        ImGui.TextDisabled("仅编辑本页草案；不保存、不写入、不自动应用。");
        ImGui.BeginDisabled();
        ImGui.Button("应用移动速度"); ImGui.SameLine(); ImGui.Button("还原移动速度");
        ImGui.EndDisabled();
        ImGui.Spacing();
        ImGui.TextWrapped("待验证：字段含义与单位 → 写入者与覆盖周期 → 对象生命周期 → 原值读取和恢复 → 自控测试服的实际位移对比。");
        ImGui.TextWrapped("接入点：IMovementSource 提供带版本、时间与来源的快照。修改事务需单独设计并验证，本版本没有移速写入适配器。");
    }
    private void Monsters()
    {
        var snapshot = monsters.Read();
        ImGui.TextColored(Accent, "03  怪物识别");
        ImGui.Text("状态：尚未接入");
        ImGui.TextWrapped(snapshot.Reason);
        ImGui.SetNextItemWidth(270);
        ImGui.InputText("名称筛选草案", ref filter, 128);
        if (ImGui.BeginTable("monsters", 5, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
        {
            foreach (var name in new[] { "名称 / ID", "分类", "距离", "生命比例", "证据时间" }) ImGui.TableSetupColumn(name);
            ImGui.TableHeadersRow();
            ImGui.TableNextRow(); ImGui.TableSetColumnIndex(0); ImGui.TextDisabled("尚无数据源");
            ImGui.EndTable();
        }
        ImGui.Spacing();
        ImGui.TextWrapped("预留快照：实体 ID、名称、分类、位置、距离、生命比例、采集时间、版本身份与来源。缺失字段保留未知，不能默认填 0。");
        ImGui.TextWrapped("接入点：IMonsterSource。后续应先用离线样本验证分类和生命周期，再验证自控测试环境中的只读快照。此页未实现实体扫描或自动操作。");
    }
    private static void EvidencePage()
    {
        ImGui.TextColored(Accent, "04  证据与接入");
        ImGui.TextWrapped("攻速核心与原 WinForms 工具共用一份源代码。新界面只管理会话和呈现状态；REA 仍负责已有静态分析证据。");
        ImGui.Separator();
        ImGui.TextWrapped("当前配置路径：" + AttackSpeedLab.Profile.GamePath);
        ImGui.TextWrapped("Game.dll SHA256：" + AttackSpeedLab.Profile.GameHash);
        ImGui.TextWrapped("注意：该路径来自旧研究环境。本机找不到目标时显示空列表；本次不修改路径或放宽版本校验。");
        ImGui.Spacing();
        ImGui.TextWrapped("验证层级：本机内存夹具通过 ≠ 游戏效果验证通过。回家后仍需验证角色动画、实际命中间隔、服务器判定和停止后的恢复情况。");
        ImGui.TextWrapped("架构与验收：同目录 architecture.html。离线入口：AionLab.exe --offline。");
    }
}
