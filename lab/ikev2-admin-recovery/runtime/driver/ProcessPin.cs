using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
// Inspector-owned process handle: PID recycling cannot turn an exited process healthy.
public sealed class ProcessPin : IDisposable {
 [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string command,out int count);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
 public static string[] Arguments(string command){
  int count;IntPtr p=CommandLineToArgvW(command,out count);if(p==IntPtr.Zero)throw new Win32Exception();
  try{var result=new string[Math.Max(0,count-1)];for(int i=1;i<count;i++)result[i-1]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(p,i*IntPtr.Size));return result;}finally{LocalFree(p);}
 }
 [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref int size);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h,uint access,out IntPtr token);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int needed);
 IntPtr handle;
 public int Pid; public string Start,Path,Sid,Integrity; public bool Elevated;
 static IntPtr Info(IntPtr token,int kind) {
  int size;GetTokenInformation(token,kind,IntPtr.Zero,0,out size);
  IntPtr p=Marshal.AllocHGlobal(size);
  if(!GetTokenInformation(token,kind,p,size,out size)){Marshal.FreeHGlobal(p);throw new Win32Exception();}
  return p;
 }
 public ProcessPin(int pid) {
  Pid=pid;handle=OpenProcess(0x00101000,false,pid);
  if(handle==IntPtr.Zero)throw new Win32Exception();
  try {
   long c,e,k,u;if(!GetProcessTimes(handle,out c,out e,out k,out u))throw new Win32Exception();
   Start=DateTime.FromFileTimeUtc(c).ToString("o");
   var b=new StringBuilder(32768);int n=b.Capacity;if(!QueryFullProcessImageName(handle,0,b,ref n))throw new Win32Exception();Path=b.ToString();
   IntPtr token;if(!OpenProcessToken(handle,8,out token))throw new Win32Exception();
   try {
    IntPtr p=Info(token,1);try{Sid=new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}finally{Marshal.FreeHGlobal(p);}
    p=Info(token,20);try{Elevated=Marshal.ReadInt32(p)!=0;}finally{Marshal.FreeHGlobal(p);}
    p=Info(token,25);try{Integrity=new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}finally{Marshal.FreeHGlobal(p);}
   } finally {CloseHandle(token);}
  } catch {Dispose();throw;}
 }
 public void RefreshToken() {
  if(!Alive)throw new InvalidOperationException("Process exited");
  IntPtr token;if(!OpenProcessToken(handle,8,out token))throw new Win32Exception();
  try {
   IntPtr p=Info(token,1);try{Sid=new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}finally{Marshal.FreeHGlobal(p);}
   p=Info(token,20);try{Elevated=Marshal.ReadInt32(p)!=0;}finally{Marshal.FreeHGlobal(p);}
   p=Info(token,25);try{Integrity=new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}finally{Marshal.FreeHGlobal(p);}
  }finally{CloseHandle(token);}
  if(!Alive)throw new InvalidOperationException("Process exited during sample");
 }
 public bool Alive {get {if(handle==IntPtr.Zero)return false;uint result=WaitForSingleObject(handle,0);if(result==0xffffffff)throw new Win32Exception();return result==258;}}
 public void Dispose(){if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
}
