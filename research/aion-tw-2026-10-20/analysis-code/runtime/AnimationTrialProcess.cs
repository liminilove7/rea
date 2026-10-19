using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class TwAnimationReadResult {
  public bool Success;
  public int Win32Error;
  public ulong Requested;
  public ulong BytesRead;
  public byte[] Bytes;
}

public sealed class TwAnimationTrialProcess : IDisposable {
  private IntPtr handle;
  private readonly ulong intervalAddress;
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

  public TwAnimationTrialProcess(int pid, string expectedPath, long expectedCreationFileTime, ulong selectedIntervalAddress) {
    if(selectedIntervalAddress<0x10000 || selectedIntervalAddress>long.MaxValue) throw new ArgumentOutOfRangeException("selectedIntervalAddress");
    intervalAddress=selectedIntervalAddress;
    // Explicit temporary experiment: VM_READ | VM_WRITE | VM_OPERATION | QUERY_LIMITED_INFORMATION.
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
  public TwAnimationReadResult Read(ulong address, int length) {
    if(handle==IntPtr.Zero) throw new ObjectDisposedException("TwAnimationTrialProcess");
    if(length<1 || length>64) throw new ArgumentOutOfRangeException("length","This experiment reads only explicit fields, up to 64 bytes per request.");
    if(address>long.MaxValue) throw new ArgumentOutOfRangeException("address");
    var data=new byte[length]; UIntPtr count;
    bool ok=ReadProcessMemory(handle,new IntPtr((long)address),data,(UIntPtr)(uint)length,out count);
    int error=ok?0:Marshal.GetLastWin32Error(); ulong actual=count.ToUInt64();
    if(actual<(ulong)data.Length) Array.Resize(ref data,(int)actual);
    return new TwAnimationReadResult { Success=ok && actual==(ulong)length,Win32Error=error,Requested=(ulong)length,BytesRead=actual,Bytes=data };
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern bool WriteProcessMemory(IntPtr h, IntPtr address, byte[] bytes, UIntPtr size, out UIntPtr written);
  public TwAnimationWriteResult ChangeAnimationU(ushort expectedCurrent, ushort desired) {
    if(!((expectedCurrent==1200 && desired==1500) || (expectedCurrent==1500 && desired==1200)))
      throw new ArgumentOutOfRangeException("desired", "Only the fixed 1200-to-1500 trial and its reversal are permitted.");
    var before=Read(intervalAddress,2);
    if(!before.Success) throw new InvalidOperationException("Cannot read trial field before writing.");
    ushort old=BitConverter.ToUInt16(before.Bytes,0);
    if(old!=expectedCurrent) return new TwAnimationWriteResult { Attempted=false,Success=false,Before=old,Desired=desired,Reason="Current value differs; no write attempted." };
    byte[] bytes=BitConverter.GetBytes(desired); UIntPtr written;
    bool ok=WriteProcessMemory(handle,new IntPtr((long)intervalAddress),bytes,(UIntPtr)2,out written);
    int error=ok?0:Marshal.GetLastWin32Error();
    var after=Read(intervalAddress,2);
    return new TwAnimationWriteResult {Attempted=true,Success=ok && written.ToUInt64()==2 && after.Success && BitConverter.ToUInt16(after.Bytes,0)==desired,Before=old,Desired=desired,BytesWritten=written.ToUInt64(),Win32Error=error,Readback=after,Reason="Sequential check/write/readback; not an atomic compare-and-swap."};
  }
  public void Dispose() {
    if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; }
  }
}

public sealed class TwAnimationWriteResult {
  public bool Attempted;
  public bool Success;
  public ushort Before;
  public ushort Desired;
  public ulong BytesWritten;
  public int Win32Error;
  public TwAnimationReadResult Readback;
  public string Reason;
}
