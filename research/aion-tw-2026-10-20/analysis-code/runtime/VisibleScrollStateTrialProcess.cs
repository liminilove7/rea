using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class TwVisibleScrollReadResult {
  public bool Success;
  public int Win32Error;
  public ulong Requested;
  public ulong BytesRead;
  public byte[] Bytes;
}

public sealed class TwVisibleScrollStateProcess : IDisposable {
  private IntPtr handle;
  private readonly ulong[] stateAddresses;
  private readonly int[] stateWidths=new int[]{2,4,2};
  public bool HasWriteAttempted { get; private set; }
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder path, ref uint size);
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern bool ReadProcessMemory(IntPtr h, IntPtr address, byte[] bytes, UIntPtr size, out UIntPtr read);
  [DllImport("kernel32.dll")]
  private static extern bool CloseHandle(IntPtr h);

  public TwVisibleScrollStateProcess(int pid, string expectedPath, long expectedCreationFileTime, ulong moduleBase, ulong component) {
    if(moduleBase<0x10000 || component<0x10000 || moduleBase>long.MaxValue-0x142DC14 || component>long.MaxValue-0x534) throw new ArgumentOutOfRangeException("selected object");
    stateAddresses=new ulong[]{moduleBase+0x142DB40, moduleBase+0x142DC10, component+0x532};
    // Explicit bounded normal-scroll-state comparison: VM_READ|VM_WRITE|VM_OPERATION|QUERY_LIMITED_INFORMATION.
    handle=OpenProcess(0x1038, false, pid);
    if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
      var path=new StringBuilder(32768); uint n=32768;
      if(!QueryFullProcessImageName(handle,0,path,ref n)) throw new Win32Exception(Marshal.GetLastWin32Error());
      long created, exited, kernel, user;
      if(!GetProcessTimes(handle,out created,out exited,out kernel,out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
      if(!String.Equals(path.ToString(),expectedPath,StringComparison.OrdinalIgnoreCase) || created!=expectedCreationFileTime)
        throw new InvalidOperationException("Process identity did not match the selected PID/path/creation time.");
    } catch { Dispose(); throw; }
  }
  public TwVisibleScrollReadResult Read(ulong address, int length) {
    if(handle==IntPtr.Zero) throw new ObjectDisposedException("TwVisibleScrollStateProcess");
    if(length<1 || length>64) throw new ArgumentOutOfRangeException("length","This experiment reads only explicit fields, up to 64 bytes per request.");
    if(address>long.MaxValue) throw new ArgumentOutOfRangeException("address");
    var data=new byte[length]; UIntPtr count;
    bool ok=ReadProcessMemory(handle,new IntPtr((long)address),data,(UIntPtr)(uint)length,out count);
    int error=ok?0:Marshal.GetLastWin32Error(); ulong actual=count.ToUInt64();
    if(actual<(ulong)data.Length) Array.Resize(ref data,(int)actual);
    return new TwVisibleScrollReadResult { Success=ok && actual==(ulong)length,Win32Error=error,Requested=(ulong)length,BytesRead=actual,Bytes=data };
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern bool WriteProcessMemory(IntPtr h, IntPtr address, byte[] data, UIntPtr size, out UIntPtr count);
  private uint ValueAt(int index) {
    var raw=Read(stateAddresses[index],stateWidths[index]);
    if(!raw.Success) throw new InvalidOperationException("Cannot read selected trial field.");
    return stateWidths[index]==2 ? BitConverter.ToUInt16(raw.Bytes,0) : BitConverter.ToUInt32(raw.Bytes,0);
  }
  private TwVisibleScrollWrite WriteField(int index,uint expected,uint desired) {
    uint before=ValueAt(index);
    if(before!=expected) return new TwVisibleScrollWrite{Index=index,Attempted=false,Success=false,Before=before,Desired=desired,Reason="Changed value; write refused"};
    byte[] bytes=stateWidths[index]==2 ? BitConverter.GetBytes((ushort)desired) : BitConverter.GetBytes(desired);
    HasWriteAttempted=true; UIntPtr count;
    bool ok=WriteProcessMemory(handle,new IntPtr((long)stateAddresses[index]),bytes,(UIntPtr)(uint)bytes.Length,out count);
    int error=ok?0:Marshal.GetLastWin32Error();
    var after=Read(stateAddresses[index],stateWidths[index]);
    bool match=after.Success && (stateWidths[index]==2 ? BitConverter.ToUInt16(after.Bytes,0) : BitConverter.ToUInt32(after.Bytes,0))==desired;
    return new TwVisibleScrollWrite{Index=index,Address=stateAddresses[index],Width=stateWidths[index],Attempted=true,Success=ok&&count.ToUInt64()==(ulong)bytes.Length&&match,Before=before,Desired=desired,BytesWritten=count.ToUInt64(),Win32Error=error,Readback=after,Reason="Sequential read/write/readback; not atomic"};
  }
  public TwVisibleScrollTransition ApplyState() {
    if(HasWriteAttempted) throw new InvalidOperationException("Single application only.");
    for(int i=0;i<3;i++) if(ValueAt(i)!=1200) return new TwVisibleScrollTransition{Success=false,Reason="Baseline tuple differs; no writes attempted",Fields=new TwVisibleScrollWrite[0]};
    var result=new System.Collections.Generic.List<TwVisibleScrollWrite>();
    for(int i=0;i<3;i++) {var row=WriteField(i,1200,800);result.Add(row);if(!row.Success) return new TwVisibleScrollTransition{Success=false,Reason="Application incomplete; check restoration record",Fields=result.ToArray()};}
    return new TwVisibleScrollTransition{Success=true,Reason="Three observed normal-scroll fields applied",Fields=result.ToArray()};
  }
  public TwVisibleScrollTransition RestoreState() {
    if(!HasWriteAttempted) return new TwVisibleScrollTransition{Success=true,Reason="No write attempted; no restoration writes",Fields=new TwVisibleScrollWrite[0]};
    for(int i=0;i<3;i++){uint v=ValueAt(i);if(v!=1200&&v!=800) return new TwVisibleScrollTransition{Success=false,Reason="External tuple value preserved; no restoration writes",Fields=new TwVisibleScrollWrite[0]};}
    var result=new System.Collections.Generic.List<TwVisibleScrollWrite>();
    for(int i=2;i>=0;i--){if(ValueAt(i)==1200) continue;var row=WriteField(i,800,1200);result.Add(row);if(!row.Success) return new TwVisibleScrollTransition{Success=false,Reason="Restoration incomplete",Fields=result.ToArray()};}
    return new TwVisibleScrollTransition{Success=true,Reason="Original values restored or already present",Fields=result.ToArray()};
  }
  public void Dispose() {
    if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; }
  }
}

public sealed class TwVisibleScrollWrite {
 public int Index; public ulong Address; public int Width; public bool Attempted; public bool Success; public uint Before; public uint Desired; public ulong BytesWritten; public int Win32Error; public TwVisibleScrollReadResult Readback; public string Reason;
}
public sealed class TwVisibleScrollTransition {public bool Success; public string Reason; public TwVisibleScrollWrite[] Fields;}
