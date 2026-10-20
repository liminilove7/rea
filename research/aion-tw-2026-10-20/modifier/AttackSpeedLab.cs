using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace AttackSpeedLab {
  // The game-specific layout is an analyst profile derived from saved REA evidence.
  // Runtime memory access below is auxiliary Win32 tooling, not a REA provider.
  internal static class Profile {
    internal const string GamePath = @"D:\Workspace\AION_TW\DeuLuncher\bin56\aion.bin";
    internal const string GameHash = "b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7";
    internal const string EngineHash = "fbca87e5a639551bf7653d464e2863c49800e73c124ae4666ea9fb11d40bef7a";
    internal const ulong Interval = 0x142DB40, Mirror = 0x142DC10;
    internal const ulong Manager = 0xF25C68, LocalHandle = 0x1422648;
    internal const ulong U = 0x530, V = 0x532, Scale = 0x51C;
  }

  internal interface IMemory : IDisposable {
    byte[] Read(ulong address, int count);
    void Write(ulong address, byte[] value);
  }

  internal sealed class NativeMemory : IMemory {
    private IntPtr handle;
    private readonly bool writable;
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder text, ref uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] data, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] data, UIntPtr size, out UIntPtr written);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr process);
    internal NativeMemory(int pid, string expectedPath, long expectedBirth, bool write) {
      writable=write;
      handle=OpenProcess(write ? 0x1038u : 0x1010u, false, pid);
      if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");
      try {
        var path=new StringBuilder(32768); uint size=32768; long birth, exit, kernel, user;
        if(!QueryFullProcessImageName(handle,0,path,ref size) || !GetProcessTimes(handle,out birth,out exit,out kernel,out user))
          throw new Win32Exception(Marshal.GetLastWin32Error());
        if(!String.Equals(path.ToString(),expectedPath,StringComparison.OrdinalIgnoreCase) || birth!=expectedBirth)
          throw new InvalidOperationException("PID、路径或启动时间不匹配，拒绝访问。");
      } catch { Dispose(); throw; }
    }
    private static IntPtr Pointer(ulong address) {
      if(address<0x10000 || address>0x00007FFFFFFFFFFFUL) throw new InvalidOperationException("无效的用户地址。");
      return new IntPtr((long)address);
    }
    public byte[] Read(ulong address, int count) {
      if(handle==IntPtr.Zero) throw new ObjectDisposedException("NativeMemory");
      if(count<1 || count>64) throw new ArgumentOutOfRangeException("count");
      byte[] data=new byte[count]; UIntPtr actual;
      bool ok=ReadProcessMemory(handle,Pointer(address),data,(UIntPtr)(uint)count,out actual);
      if(!ok || actual.ToUInt64()!=(ulong)count)
        throw new Win32Exception(Marshal.GetLastWin32Error(),"ReadProcessMemory 0x"+address.ToString("x")+" bytes="+actual);
      return data;
    }
    public void Write(ulong address, byte[] value) {
      if(handle==IntPtr.Zero) throw new ObjectDisposedException("NativeMemory");
      if(!writable || (value.Length!=2 && value.Length!=4)) throw new InvalidOperationException("写入权限或字段宽度不符。");
      UIntPtr actual;
      bool ok=WriteProcessMemory(handle,Pointer(address),value,(UIntPtr)(uint)value.Length,out actual);
      if(!ok || actual.ToUInt64()!=(ulong)value.Length)
        throw new Win32Exception(Marshal.GetLastWin32Error(),"WriteProcessMemory incomplete: "+actual);
    }
    public void Dispose() { if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; } }
  }

  internal static class Mem {
    internal static ulong U64(IMemory m, ulong a) { return BitConverter.ToUInt64(m.Read(a,8),0); }
    internal static ushort U16(IMemory m, ulong a) { return BitConverter.ToUInt16(m.Read(a,2),0); }
    internal static uint Value(IMemory m, ulong a, int width) {
      byte[] bytes=m.Read(a,width);
      return width==2 ? BitConverter.ToUInt16(bytes,0) : BitConverter.ToUInt32(bytes,0);
    }
    internal static string Hex(ulong address) { return "0x"+address.ToString("x"); }
  }

  internal sealed class Role {
    internal ulong Entity, Character, Vtable, Node;
    internal ushort Handle;
    internal static Role Resolve(IMemory m, ulong b, ulong engine) {
      ushort key=Mem.U16(m,b+Profile.LocalHandle);
      ulong manager=Mem.U64(m,b+Profile.Manager), head=Mem.U64(m,manager+0x58);
      byte[] header=m.Read(head,48);
      if(header[25]!=1) throw new InvalidOperationException("实体表哨兵格式不匹配。");
      ulong node=BitConverter.ToUInt64(header,8), lower=head;
      var visited=new HashSet<ulong>(); bool ended=false;
      for(int depth=0;depth<32;depth++) {
        if(!visited.Add(node)) throw new InvalidOperationException("实体表存在循环。");
        byte[] raw=m.Read(node,48);
        if(raw[25]!=0) { ended=true; break; }
        ushort found=BitConverter.ToUInt16(raw,32);
        if(found>=key) { lower=node; node=BitConverter.ToUInt64(raw,0); }
        else node=BitConverter.ToUInt64(raw,16);
      }
      if(!ended || lower==head) throw new InvalidOperationException("没有找到当前角色，或超过32层遍历界限。");
      byte[] entry=m.Read(lower,48);
      if(BitConverter.ToUInt16(entry,32)!=key) throw new InvalidOperationException("当前句柄未精确命中。");
      ulong entity=BitConverter.ToUInt64(entry,40), evt=Mem.U64(m,entity);
      if(Mem.U64(m,evt+0xC0)!=engine+0x19190) throw new InvalidOperationException("实体容器入口版本不匹配。");
      ulong c=Mem.U64(m,entity+0x380), vt=Mem.U64(m,c);
      if(vt!=b+0xD53940 || Mem.U64(m,vt+0x50)!=b+0x11C950 || Mem.U64(m,vt+8)!=b+0x1652A0 || Mem.U64(m,c+8)!=entity)
        throw new InvalidOperationException("Player虚表或实体回链不匹配。");
      string bytes=BitConverter.ToString(m.Read(b+0x11C950,21)).Replace("-","").ToLowerInvariant();
      if(bytes!="83fa027706498908b001c349c7000000000032c0c3") throw new InvalidOperationException("运行中类型查询代码与REA样本不符。");
      byte[] confirm=m.Read(lower,48);
      if(Mem.U16(m,b+Profile.LocalHandle)!=key || BitConverter.ToUInt64(confirm,40)!=entity || BitConverter.ToUInt16(confirm,32)!=key || Mem.U64(m,entity+0x380)!=c)
        throw new InvalidOperationException("顺序读取期间角色发生变化。");
      return new Role { Entity=entity,Character=c,Vtable=vt,Node=lower,Handle=key };
    }
    internal bool Same(Role other) {
      return Entity==other.Entity && Character==other.Character && Vtable==other.Vtable && Node==other.Node && Handle==other.Handle;
    }
  }

  internal sealed class Target {
    internal int Pid;
    internal long Birth;
    internal ulong Base, Engine;
    internal string Path;
    internal static string Hash(string path) {
      using(var input=File.OpenRead(path)) using(var sha=SHA256.Create())
        return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();
    }
    internal static Target Capture(int pid) {
      using(var p=Process.GetProcessById(pid)) {
        string path=p.MainModule.FileName; long birth=p.StartTime.ToUniversalTime().ToFileTimeUtc();
        if(!String.Equals(path,Profile.GamePath,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("目标路径不在本研究版本内。");
        ProcessModule game=null, engine=null;
        foreach(ProcessModule mod in p.Modules) {
          if(String.Equals(mod.ModuleName,"Game.dll",StringComparison.OrdinalIgnoreCase)) { if(game!=null) throw new InvalidOperationException("Game.dll不唯一。"); game=mod; }
          if(String.Equals(mod.ModuleName,"CryEntitySystem.dll",StringComparison.OrdinalIgnoreCase)) engine=mod;
        }
        if(game==null || engine==null || !String.Equals(System.IO.Path.GetDirectoryName(game.FileName),System.IO.Path.GetDirectoryName(path),StringComparison.OrdinalIgnoreCase) ||
          !String.Equals(System.IO.Path.GetDirectoryName(engine.FileName),System.IO.Path.GetDirectoryName(path),StringComparison.OrdinalIgnoreCase) ||
          Hash(game.FileName)!=Profile.GameHash || Hash(engine.FileName)!=Profile.EngineHash)
          throw new InvalidOperationException("加载模块路径或SHA256不匹配，拒绝复用偏移。");
        if(game.ModuleMemorySize<=0x142DC14) throw new InvalidOperationException("模块范围不足。");
        return new Target { Pid=pid,Path=path,Birth=birth,Base=(ulong)game.BaseAddress.ToInt64(),Engine=(ulong)engine.BaseAddress.ToInt64() };
      }
    }
    // Cheap identity/module check each active tick; full file hashes are checked at connect/apply.
    internal void Check() {
      using(var p=Process.GetProcessById(Pid)) {
        if(p.StartTime.ToUniversalTime().ToFileTimeUtc()!=Birth || !String.Equals(p.MainModule.FileName,Path,StringComparison.OrdinalIgnoreCase))
          throw new InvalidOperationException("进程身份已变化。");
        bool game=false,engine=false;
        foreach(ProcessModule mod in p.Modules) {
          if(mod.ModuleName.Equals("Game.dll",StringComparison.OrdinalIgnoreCase)) game=(ulong)mod.BaseAddress.ToInt64()==Base;
          if(mod.ModuleName.Equals("CryEntitySystem.dll",StringComparison.OrdinalIgnoreCase)) engine=(ulong)mod.BaseAddress.ToInt64()==Engine;
        }
        if(!game || !engine) throw new InvalidOperationException("加载基址已变化。");
      }
    }
    public override string ToString() { return "aion.bin · PID "+Pid; }
  }

  internal sealed class Audit : IDisposable {
    private readonly FileStream stream;
    private readonly JavaScriptSerializer serializer=new JavaScriptSerializer();
    internal readonly string FileName;
    internal Audit(string directory) {
      Directory.CreateDirectory(directory);
      FileName=System.IO.Path.Combine(directory,DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff")+"-"+Guid.NewGuid().ToString("N")+".jsonl");
      stream=new FileStream(FileName,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough);
    }
    internal void Record(string phase, object details) {
      byte[] bytes=Encoding.UTF8.GetBytes(serializer.Serialize(new { utc=DateTime.UtcNow.ToString("o"),phase=phase,details=details })+"\n");
      stream.Write(bytes,0,bytes.Length); stream.Flush(true);
    }
    public void Dispose() { stream.Dispose(); }
  }

  internal sealed class Field {
    internal string Name; internal ulong Address; internal int Width;
    internal uint Original; internal bool Attempted;
  }

  // This transaction owns only three typed fields and never freezes/reapplies a value.
  internal sealed class Mutation {
    private readonly IMemory memory;
    private readonly Action validate;
    private readonly Action<string,object> audit;
    internal readonly Field[] Fields;
    internal readonly uint Desired;
    private bool started;
    internal Mutation(IMemory memory, ulong b, ulong c, uint desired, Action validate, Action<string,object> audit) {
      if(desired<700 || desired>1200) throw new ArgumentOutOfRangeException("desired","当前教学范围为700至1200，并非服务器上限。");
      this.memory=memory; this.validate=validate; this.audit=audit; Desired=desired;
      Fields=new[] { new Field{Name="I",Address=b+Profile.Interval,Width=2},new Field{Name="Mirror",Address=b+Profile.Mirror,Width=4},new Field{Name="V",Address=c+Profile.V,Width=2} };
    }
    private void Change(Field f, uint expected, uint desired, string phase) {
      validate(); uint before=Mem.Value(memory,f.Address,f.Width);
      if(before!=expected) throw new InvalidOperationException(f.Name+"已被外部更新，拒绝覆盖。");
      audit(phase+"-intent",new { field=f.Name,address=Mem.Hex(f.Address),width=f.Width,before=before,desired=desired });
      // Mark before the API call: an exception or short write may still have changed memory.
      f.Attempted=true;
      memory.Write(f.Address,f.Width==2 ? BitConverter.GetBytes((ushort)desired) : BitConverter.GetBytes(desired));
      uint actual=Mem.Value(memory,f.Address,f.Width);
      audit(phase+"-readback",new { field=f.Name,value=actual });
      if(actual!=desired) throw new InvalidOperationException(f.Name+"写入后回读不匹配。");
    }
    internal void Apply() {
      if(started) throw new InvalidOperationException("同一事务不能重复应用。");
      started=true; validate();
      foreach(Field f in Fields) { f.Original=Mem.Value(memory,f.Address,f.Width); if(f.Original!=1200) throw new InvalidOperationException("当前工具仅支持原武器、无攻速增益的1200基线。"); }
      audit("baseline",new { original=new uint[]{Fields[0].Original,Fields[1].Original,Fields[2].Original},desired=Desired });
      foreach(Field f in Fields) Change(f,1200,Desired,"apply");
    }
    internal void CheckCurrent() {
      validate();
      foreach(Field f in Fields) if(Mem.Value(memory,f.Address,f.Width)!=Desired) throw new InvalidOperationException("客户端数值已外部更新；停止实验并尝试还原。不会重新锁定。");
    }
    internal string[] Restore() {
      var problems=new List<string>();
      for(int i=Fields.Length-1;i>=0;i--) {
        Field f=Fields[i]; if(!f.Attempted) continue;
        try {
          validate(); uint value=Mem.Value(memory,f.Address,f.Width);
          if(value==f.Original) { f.Attempted=false; continue; }
          if(value!=Desired) { problems.Add(f.Name+"外部值"+value+"已保留；未强制写回"); continue; }
          // Restoration must proceed even when the audit disk becomes unavailable.
          try { audit("restore-intent",new { field=f.Name,address=Mem.Hex(f.Address),before=value,desired=f.Original }); } catch(Exception e) { problems.Add("日志失败："+e.Message); }
          validate();
          if(Mem.Value(memory,f.Address,f.Width)!=Desired) throw new InvalidOperationException("还原前数值再次变化。");
          memory.Write(f.Address,f.Width==2 ? BitConverter.GetBytes((ushort)f.Original) : BitConverter.GetBytes(f.Original));
          uint actual=Mem.Value(memory,f.Address,f.Width);
          if(actual!=f.Original) throw new InvalidOperationException("还原回读失败。");
          f.Attempted=false;
          try { audit("restore-readback",new { field=f.Name,value=actual }); } catch(Exception e) { problems.Add("日志失败："+e.Message); }
        } catch(Exception e) { problems.Add(f.Name+"："+e.Message); }
      }
      return problems.ToArray();
    }
  }

  internal sealed class Session : IDisposable {
    internal readonly Target Target; internal readonly Role Role;
    private readonly NativeMemory memory; private readonly Audit audit; private readonly Mutation mutation;
    internal readonly Stopwatch Elapsed=new Stopwatch();
    internal string LogPath { get { return audit.FileName; } }
    private Session(Target target, NativeMemory memory, Role role, Audit audit, uint desired) {
      Target=target; this.memory=memory; Role=role; this.audit=audit;
      mutation=new Mutation(memory,target.Base,role.Character,desired,Validate,audit.Record);
    }
    private void Validate() {
      Target.Check(); Role current=Role.Resolve(memory,Target.Base,Target.Engine);
      if(!Role.Same(current)) throw new InvalidOperationException("角色对象已重建；禁止写入旧对象。");
      if(Mem.U16(memory,Role.Character+Profile.U)!=1200 || BitConverter.ToSingle(memory.Read(Role.Character+Profile.Scale,4),0)!=1f)
        throw new InvalidOperationException("U或动画系数不再符合该实验配置。");
    }
    internal static Session Begin(int pid, uint desired, string logDirectory) {
      Target target=Target.Capture(pid); NativeMemory m=null; Audit a=null; Session s=null;
      try {
        m=new NativeMemory(pid,target.Path,target.Birth,true);
        Role role=Role.Resolve(m,target.Base,target.Engine);
        a=new Audit(logDirectory); s=new Session(target,m,role,a,desired);
        a.Record("session",new { pid=pid,path=target.Path,birthUtc=DateTime.FromFileTimeUtc(target.Birth).ToString("o"),gameSha256=Profile.GameHash,gameBase=Mem.Hex(target.Base),entity=Mem.Hex(role.Entity),character=Mem.Hex(role.Character),desired=desired,maximumSeconds=60 });
        s.mutation.Apply(); s.Elapsed.Start(); return s;
      } catch(Exception failure) {
        string[] restore=s==null ? new string[0] : s.mutation.Restore();
        if(m!=null) m.Dispose(); if(a!=null) a.Dispose();
        throw new InvalidOperationException(failure.Message+(restore.Length>0 ? "\n还原存在问题："+String.Join("；",restore) : "\n已尝试还原本次写入。"),failure);
      }
    }
    internal void Poll() { mutation.CheckCurrent(); }
    internal string[] Stop() {
      string[] errors=mutation.Restore();
      try { audit.Record("completed",new { elapsedSeconds=Elapsed.Elapsed.TotalSeconds,restorationIssues=errors }); }
      catch(Exception e) { var all=new List<string>(errors); all.Add("日志："+e.Message); errors=all.ToArray(); }
      return errors;
    }
    public void Dispose() { memory.Dispose(); audit.Dispose(); }
  }

  internal sealed class LabForm : Form {
    private readonly ComboBox targets=new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList,Width=310 };
    private readonly NumericUpDown desired=new NumericUpDown { Minimum=700,Maximum=1200,Value=700,Increment=100,Width=100 };
    private readonly Button refresh=new Button { Text="刷新目标",AutoSize=true }, inspect=new Button { Text="只读检查",AutoSize=true };
    private readonly Button start=new Button { Text="开始 60 秒实验",AutoSize=true }, stop=new Button { Text="立即还原",AutoSize=true,Enabled=false };
    private readonly TextBox output=new TextBox { Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,Font=new Font("Consolas",10) };
    private readonly Label status=new Label { Text="未连接；尚未读写游戏",AutoSize=true,ForeColor=Color.DarkSlateBlue };
    private readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer { Interval=500 };
    private Session active;
    internal LabForm() : this(true) { }
    internal LabForm(bool discover) {
      Text="AION 攻速实验工具 · 可见 / 可还原"; Size=new Size(1000,760); MinimumSize=new Size(1000,760);
      Font=new Font("Microsoft YaHei UI",10); StartPosition=FormStartPosition.CenterScreen;
      var layout=new TableLayoutPanel { Dock=DockStyle.Fill,RowCount=7,ColumnCount=1,Padding=new Padding(20) };
      for(int i=0;i<6;i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
      layout.Controls.Add(new Label { Text="基于 Game.dll 基址 + 偏移的攻速实验",AutoSize=true,Font=new Font(Font.FontFamily,16,FontStyle.Bold),Margin=new Padding(0,0,0,12) });
      layout.Controls.Add(new Label { Text="原武器、无攻速卷轴、非战斗时开始。当前仅支持 I / 镜像 / U / V 均为 1200、系数为 1 的配置。\n数值更小代表客户端间隔更短；实际服务器命中频率需另证。只应用一次，不持续锁定。",AutoSize=true,MaximumSize=new Size(840,0),Margin=new Padding(0,0,0,12) });
      var row=new FlowLayoutPanel { AutoSize=true,Dock=DockStyle.Fill }; row.Controls.Add(targets); row.Controls.Add(refresh); row.Controls.Add(inspect); layout.Controls.Add(row);
      var controls=new FlowLayoutPanel { AutoSize=true,Dock=DockStyle.Fill }; controls.Controls.Add(new Label { Text="目标间隔",AutoSize=true,Padding=new Padding(0,7,0,0) }); controls.Controls.Add(desired); controls.Controls.Add(start); controls.Controls.Add(stop); layout.Controls.Add(controls);
      layout.Controls.Add(status);
      layout.Controls.Add(new Label { Text="每次重新定位角色。正常关闭 / 超时会尝试还原；强制结束、断电或角色重建时无法保证还原。\n工具无自启、驱动、注入或隐藏；日志保存在本目录 logs。",AutoSize=true,ForeColor=Color.DimGray,Margin=new Padding(0,10,0,10) });
      layout.Controls.Add(output); Controls.Add(layout);
      refresh.Click+=delegate { RefreshTargets(); }; inspect.Click+=delegate { Inspect(); }; start.Click+=delegate { StartTrial(); }; stop.Click+=delegate { StopTrial("手动停止"); };
      timer.Tick+=delegate { if(active==null) return; try { if(active.Elapsed.Elapsed.TotalSeconds>=60) { StopTrial("60秒已到"); return; } active.Poll(); status.Text="实验中 · 剩余 "+Math.Ceiling(60-active.Elapsed.Elapsed.TotalSeconds)+" 秒 · 可开始平砍观察"; } catch(Exception e) { Append(e.Message); StopTrial("数值或对象发生变化"); } };
      FormClosing+=delegate { if(active!=null) StopTrial("关闭窗口"); };
      FormClosed+=delegate { timer.Dispose(); };
      if(discover) RefreshTargets();
      else Append("界面离线预览：未枚举或连接游戏。点击只读检查前需选择目标。");
    }
    internal void RenderPreview(string file) {
      // Render only this app's offscreen controls; no desktop/window capture.
      Size=new Size(1000,760); StartPosition=FormStartPosition.Manual; Location=new Point(-32000,-32000); ShowInTaskbar=false;
      Show(); PerformLayout(); Application.DoEvents();
      try { using(var bitmap=new Bitmap(Width,Height)) { DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height)); bitmap.Save(file,System.Drawing.Imaging.ImageFormat.Png); } }
      finally { Hide(); }
      if(!start.Enabled || stop.Enabled || desired.Value!=700 || targets.Items.Count!=0 || active!=null || timer.Enabled || output.Height<180)
        throw new InvalidOperationException("Initial UI state/layout check failed");
      File.WriteAllText(file+".json",new JavaScriptSerializer().Serialize(new { allPassed=true,checks=new[]{"No discovery or game connection in offline render","Start enabled, restoration disabled initially","Default interval 700","No active timer/session","Log area has usable height"},render="WinForms DrawToBitmap of own offscreen form, not desktop capture",width=Width,height=Height }),new UTF8Encoding(false));
    }
    private void Append(string text) { output.AppendText(DateTime.Now.ToString("HH:mm:ss")+" "+text+Environment.NewLine); }
    private void RefreshTargets() {
      targets.Items.Clear();
      foreach(int pid in Program.DiscoverTargets()) targets.Items.Add(pid);
      if(targets.Items.Count>0) targets.SelectedIndex=0;
      Append("找到 "+targets.Items.Count+" 个指定路径的 aion.bin；刷新不访问目标内存。");
    }
    private int SelectedPid() { if(targets.SelectedItem==null) throw new InvalidOperationException("请先启动研究客户端，再刷新目标。"); return (int)targets.SelectedItem; }
    private void Inspect() {
      try { Append(Program.Inspect(SelectedPid())); status.Text="只读检查完成；尚未修改"; } catch(Exception e) { Append("检查失败："+e.Message); }
    }
    private void StartTrial() {
      if(active!=null) return;
      try {
        active=Session.Begin(SelectedPid(),(uint)desired.Value,System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"logs"));
        start.Enabled=inspect.Enabled=refresh.Enabled=targets.Enabled=desired.Enabled=false; stop.Enabled=true;
        Append("已应用：I / 镜像 / V → "+desired.Value+"，U保持1200。现在开始平砍观察。\nB="+Mem.Hex(active.Target.Base)+"  C="+Mem.Hex(active.Role.Character)+"\n日志："+active.LogPath);
        status.Text="已应用 · 60 秒后尝试还原"; timer.Start();
      } catch(Exception e) { Append("未开始 / 中止："+e.Message); MessageBox.Show(this,e.Message,"未完成实验",MessageBoxButtons.OK,MessageBoxIcon.Warning); }
    }
    private void StopTrial(string reason) {
      timer.Stop(); Session s=active; active=null;
      if(s==null) return;
      string[] errors;
      try { errors=s.Stop(); } catch(Exception e) { errors=new[]{e.Message}; } finally { s.Dispose(); }
      Append(reason+"："+(errors.Length==0 ? "原值已逐项回读确认。" : String.Join("；",errors)));
      status.Text=errors.Length==0 ? "已还原并关闭进程句柄" : "还原存在未解决项；请查看记录";
      start.Enabled=inspect.Enabled=refresh.Enabled=targets.Enabled=desired.Enabled=true; stop.Enabled=false;
      if(errors.Length>0) MessageBox.Show(this,String.Join(Environment.NewLine,errors)+"\n未覆盖未知外部值；没有继续锁定。可通过正常重登重新同步角色状态。","还原结果需检查",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    }
  }

  internal static class Program {
    internal static bool CandidateName(string name) {
      // Windows preserves the .bin extension in ProcessName; it is not always aion.
      return name.Equals("aion.bin",StringComparison.OrdinalIgnoreCase) || name.Equals("aion",StringComparison.OrdinalIgnoreCase);
    }
    internal static List<int> DiscoverTargets() {
      var result=new List<int>();
      foreach(Process p in Process.GetProcesses()) using(p) {
        try { if(CandidateName(p.ProcessName) && String.Equals(p.MainModule.FileName,Profile.GamePath,StringComparison.OrdinalIgnoreCase)) result.Add(p.Id); }
        catch(Win32Exception) { } catch(InvalidOperationException) { }
      }
      return result;
    }
    internal static string Inspect(int pid) {
      Target target=Target.Capture(pid);
      using(var m=new NativeMemory(pid,target.Path,target.Birth,false)) {
        Role role=Role.Resolve(m,target.Base,target.Engine); target.Check();
        return new JavaScriptSerializer().Serialize(new { method="Auxiliary Win32 read only; REA-derived profile",memoryWritten=false,pid=pid,gameBase=Mem.Hex(target.Base),character=Mem.Hex(role.Character),I=Mem.U16(m,target.Base+Profile.Interval),mirror=Mem.Value(m,target.Base+Profile.Mirror,4),U=Mem.U16(m,role.Character+Profile.U),V=Mem.U16(m,role.Character+Profile.V),scale=BitConverter.ToSingle(m.Read(role.Character+Profile.Scale,4),0),gameHash=Profile.GameHash,atomicSnapshot=false });
      }
    }
    [STAThread]
    private static int Main(string[] args) {
      try {
        if(args.Length==2 && args[0]=="--self-test") { SelfTest.Run(args[1]); return 0; }
        if(args.Length==2 && args[0]=="--discover") { File.WriteAllText(args[1],new JavaScriptSerializer().Serialize(new { targets=DiscoverTargets(),memoryWritten=false }),new UTF8Encoding(false)); return 0; }
        if(args.Length==2 && args[0]=="--ui-preview") {
          Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
          using(var form=new LabForm(false)) form.RenderPreview(args[1]); return 0;
        }
        if(args.Length==3 && args[0]=="--inspect") { File.WriteAllText(args[2],Inspect(Int32.Parse(args[1])),new UTF8Encoding(false)); return 0; }
        if(args.Length!=0) return 2;
        bool created;
        using(var single=new Mutex(true,@"Local\REA-AionTW-AttackSpeedLab-Visible",out created)) {
          if(!created) { MessageBox.Show("攻速实验工具已经打开。请使用现有窗口。 "); return 1; }
          try { Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); Application.Run(new LabForm()); }
          finally { single.ReleaseMutex(); }
        }
        return 0;
      } catch(Exception e) {
        if(args.Length>0) { File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"last-command-error.txt"),e.ToString()); return 1; }
        MessageBox.Show(e.Message,"攻速实验工具",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1;
      }
    }
  }

  // Native scratch-memory tests are compiled in; this entry point never discovers a game.
  internal static class SelfTest {
    private sealed class FaultMemory : IMemory {
      private readonly IMemory inner; internal int Writes; internal int FailAt;
      internal FaultMemory(IMemory inner) { this.inner=inner; }
      public byte[] Read(ulong a,int n) { return inner.Read(a,n); }
      public void Write(ulong a,byte[] b) { Writes++; if(Writes==FailAt) throw new IOException("Injected write failure"); inner.Write(a,b); }
      public void Dispose() { }
    }
    internal static void Run(string output) {
      var checks=new List<string>();
      Action<bool,string> check=delegate(bool ok,string name) { if(!ok) throw new Exception(name); checks.Add(name); };
      check(Program.CandidateName("Aion.bin") && Program.CandidateName("aion") && !Program.CandidateName("aioncefprocess"),"Windows observed Aion.bin process name is discoverable; CEF excluded");
      IntPtr scratch=Marshal.AllocHGlobal(0x1A00000);
      try {
        byte[] zero=new byte[0x1A00000]; Marshal.Copy(zero,0,scratch,zero.Length);
        ulong b=(ulong)scratch.ToInt64(), engine=b+0x1500000, manager=b+0x1600000, head=manager+0x100, node=head+0x100, entity=node+0x100, c=entity+0x1000, evt=c+0x3000;
        Action<ulong,ulong> set64=delegate(ulong a,ulong v) { Marshal.WriteInt64(new IntPtr((long)a),(long)v); };
        Action<ulong,int> set16=delegate(ulong a,int v) { Marshal.WriteInt16(new IntPtr((long)a),(short)v); };
        Action<ulong,int> set32=delegate(ulong a,int v) { Marshal.WriteInt32(new IntPtr((long)a),v); };
        set64(b+Profile.Manager,manager); set16(b+Profile.LocalHandle,65535); set64(manager+0x58,head); set64(head+8,node); Marshal.WriteByte(new IntPtr((long)head),25,1);
        set64(node,head); set64(node+16,head); set16(node+32,65535); set64(node+40,entity); set64(entity,evt); set64(evt+0xC0,engine+0x19190); set64(entity+0x380,c);
        set64(c,b+0xD53940); set64(c+8,entity); set64(b+0xD53940+0x50,b+0x11C950); set64(b+0xD53940+8,b+0x1652A0);
        byte[] code=new byte[]{0x83,0xfa,0x02,0x77,0x06,0x49,0x89,0x08,0xb0,0x01,0xc3,0x49,0xc7,0,0,0,0,0,0x32,0xc0,0xc3}; Marshal.Copy(code,0,new IntPtr((long)(b+0x11C950)),code.Length);
        Action reset=delegate { set16(b+Profile.Interval,1200); set32(b+Profile.Mirror,1200); set16(c+Profile.V,1200); set16(c+Profile.U,1200); };
        reset(); Marshal.WriteByte(new IntPtr((long)(b+Profile.Interval+2)),0,0xA5); Marshal.WriteByte(new IntPtr((long)(c+Profile.V+2)),0,0x5A);
        using(var own=Process.GetCurrentProcess()) using(var m=new NativeMemory(own.Id,own.MainModule.FileName,own.StartTime.ToUniversalTime().ToFileTimeUtc(),true)) {
          Role r=Role.Resolve(m,b,engine); check(r.Character==c && r.Entity==entity,"REA-derived entity-map resolver accepts native synthetic fixture");
          set64(node,node); bool bad=false; try { Role.Resolve(m,b,engine); } catch(InvalidOperationException) { bad=true; } check(bad,"Resolver rejects repeated map node"); set64(node,head);
          set64(c+8,entity+8); bad=false; try { Role.Resolve(m,b,engine); } catch(InvalidOperationException) { bad=true; } check(bad,"Resolver rejects wrong entity backlink"); set64(c+8,entity);
          Action valid=delegate { if(!r.Same(Role.Resolve(m,b,engine))) throw new InvalidOperationException("role changed"); };
          Action<string,object> log=delegate { };
          var tx=new Mutation(m,b,c,700,valid,log); tx.Apply();
          check(Mem.U16(m,b+Profile.Interval)==700 && Mem.Value(m,b+Profile.Mirror,4)==700 && Mem.U16(m,c+Profile.V)==700,"Three fields use u16 / u32 / u16 exact writes");
          check(m.Read(b+Profile.Interval+2,1)[0]==0xA5 && m.Read(c+Profile.V+2,1)[0]==0x5A && Mem.U16(m,c+Profile.U)==1200,"Adjacent bytes and U unchanged");
          check(tx.Restore().Length==0 && Mem.U16(m,b+Profile.Interval)==1200 && Mem.U16(m,c+Profile.V)==1200,"Successful native restore/readback");
          bad=false; try { tx.Apply(); } catch(InvalidOperationException) { bad=true; } check(bad,"Same transaction cannot reapply");
          set32(b+Profile.Mirror,1092); var fault=new FaultMemory(m); tx=new Mutation(fault,b,c,700,valid,log); bad=false;
          try { tx.Apply(); } catch(InvalidOperationException) { bad=true; } check(bad && fault.Writes==0,"Mismatched buff baseline refuses every write"); reset();
          fault=new FaultMemory(m) { FailAt=2 }; tx=new Mutation(fault,b,c,800,valid,log); bad=false;
          try { tx.Apply(); } catch(IOException) { bad=true; } string[] errors=tx.Restore();
          check(bad && errors.Length==0 && Mem.U16(m,b+Profile.Interval)==1200 && Mem.Value(m,b+Profile.Mirror,4)==1200,"Partial-application exception restores earlier field");
          tx=new Mutation(m,b,c,900,valid,log); tx.Apply(); set32(b+Profile.Mirror,1092); errors=tx.Restore();
          check(errors.Length==1 && Mem.Value(m,b+Profile.Mirror,4)==1092 && Mem.U16(m,b+Profile.Interval)==1200 && Mem.U16(m,c+Profile.V)==1200,"Restoration preserves external field while recovering owned fields"); reset();
          bool identity=true; tx=new Mutation(m,b,c,700,delegate { if(!identity) throw new InvalidOperationException("role replaced"); },log); tx.Apply(); identity=false; errors=tx.Restore();
          check(errors.Length==3 && Mem.U16(m,b+Profile.Interval)==700,"Changed role refuses writes to historical addresses"); identity=true; check(tx.Restore().Length==0,"Fixture restoration possible after identity test guard reset");
          tx=new Mutation(m,b,c,800,valid,log); tx.Apply(); set16(c+Profile.V,1092); bad=false; try { tx.CheckCurrent(); } catch(InvalidOperationException) { bad=true; }
          check(bad && Mem.U16(m,c+Profile.V)==1092,"External update ends observation without reapplying"); tx.Restore(); reset();
          int auditCalls=0; tx=new Mutation(m,b,c,700,valid,delegate { if(++auditCalls>7) throw new IOException("disk unavailable"); }); tx.Apply(); errors=tx.Restore();
          check(errors.Length>0 && Mem.U16(m,b+Profile.Interval)==1200 && Mem.Value(m,b+Profile.Mirror,4)==1200 && Mem.U16(m,c+Profile.V)==1200,"Restoration still writes originals when audit storage fails");
          bad=false; try { new Mutation(m,b,c,699,valid,log); } catch(ArgumentOutOfRangeException) { bad=true; } check(bad,"Invalid target rejected before transaction");
          using(var readOnly=new NativeMemory(own.Id,own.MainModule.FileName,own.StartTime.ToUniversalTime().ToFileTimeUtc(),false)) {
            bad=false; try { readOnly.Write(b+Profile.Interval,BitConverter.GetBytes((ushort)700)); } catch(InvalidOperationException) { bad=true; } check(bad,"Read-only inspection cannot write");
          }
          bad=false; try { using(var wrong=new NativeMemory(own.Id,own.MainModule.FileName,own.StartTime.ToUniversalTime().ToFileTimeUtc()+1,false)) { } } catch(InvalidOperationException) { bad=true; } check(bad,"Handle rejects process birth mismatch");
        }
      } finally { Marshal.FreeHGlobal(scratch); }
      File.WriteAllText(output,new JavaScriptSerializer().Serialize(new { allPassed=true,checks=checks,scope="Native scratch memory in this helper process only; no game modification and no server-hit-rate proof" }),new UTF8Encoding(false));
    }
  }
}
