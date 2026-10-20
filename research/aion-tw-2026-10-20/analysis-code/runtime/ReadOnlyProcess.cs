using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class TwReadResult {
  public bool Success;
  public int Win32Error;
  public ulong Requested;
  public ulong BytesRead;
  public byte[] Bytes;
}

public sealed class TwReadOnlyProcess : IDisposable {
  private IntPtr handle;
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

  public TwReadOnlyProcess(int pid, string expectedPath, long expectedCreationFileTime) {
    // PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION only.
    handle=OpenProcess(0x1010, false, pid);
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
  public TwReadResult Read(ulong address, int length) {
    if(handle==IntPtr.Zero) throw new ObjectDisposedException("TwReadOnlyProcess");
    if(length<1 || length>64) throw new ArgumentOutOfRangeException("length","This experiment reads only explicit fields, up to 64 bytes per request.");
    if(address>long.MaxValue) throw new ArgumentOutOfRangeException("address");
    var data=new byte[length]; UIntPtr count;
    bool ok=ReadProcessMemory(handle,new IntPtr((long)address),data,(UIntPtr)(uint)length,out count);
    int error=ok?0:Marshal.GetLastWin32Error(); ulong actual=count.ToUInt64();
    if(actual<(ulong)data.Length) Array.Resize(ref data,(int)actual);
    return new TwReadResult { Success=ok && actual==(ulong)length,Win32Error=error,Requested=(ulong)length,BytesRead=actual,Bytes=data };
  }
  public void Dispose() {
    if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; }
  }
}
