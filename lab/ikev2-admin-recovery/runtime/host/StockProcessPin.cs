using System.Collections.Generic;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
// Inspector-owned process handle: PID recycling cannot turn an exited process healthy.
public sealed partial class StockProcessPin : IDisposable {
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
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr handle,uint code);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
 bool retirementRequested;
 readonly bool mayRetire;
 public uint LogonHigh,LogonLow,Session;
 public long CreationFileTime;
 public uint ExitCode {get {uint code;if(Alive || !GetExitCodeProcess(handle,out code))throw new InvalidOperationException("Exit unavailable");return code;}}
 public void Retire() {
  if(!mayRetire)throw new InvalidOperationException("Read-only process pin");
  if(retirementRequested)throw new InvalidOperationException("Retirement already requested");
  if(!Alive)return;
  retirementRequested=true;
  if(!TerminateProcess(handle,1))throw new Win32Exception();
  if(WaitForSingleObject(handle,30000)!=0)throw new InvalidOperationException("Private exit unresolved");
 }
 public int Pid; public string Start,Path,Sid,Integrity; public bool Elevated;
 static IntPtr Info(IntPtr token,int kind) {
  int size;GetTokenInformation(token,kind,IntPtr.Zero,0,out size);
  IntPtr p=Marshal.AllocHGlobal(size);
  if(!GetTokenInformation(token,kind,p,size,out size)){Marshal.FreeHGlobal(p);throw new Win32Exception();}
  return p;
 }
 public StockProcessPin(int pid) : this(pid,false) {}
 public StockProcessPin(int pid,bool retirement) {
  mayRetire=retirement;
  Pid=pid;handle=OpenProcess(retirement ? 0x00101001u : 0x00101000u,false,pid);
  if(handle==IntPtr.Zero)throw new Win32Exception();
  try {
   long c,e,k,u;if(!GetProcessTimes(handle,out c,out e,out k,out u))throw new Win32Exception();
   CreationFileTime=c;Start=DateTime.FromFileTimeUtc(c).ToString("o");
   var b=new StringBuilder(32768);int n=b.Capacity;if(!QueryFullProcessImageName(handle,0,b,ref n))throw new Win32Exception();Path=b.ToString();
   IntPtr token;if(!OpenProcessToken(handle,8,out token))throw new Win32Exception();
   try {
    IntPtr p=Info(token,1);try{Sid=new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}finally{Marshal.FreeHGlobal(p);}
    p=Info(token,10);try{LogonLow=unchecked((uint)Marshal.ReadInt32(p,8));LogonHigh=unchecked((uint)Marshal.ReadInt32(p,12));}finally{Marshal.FreeHGlobal(p);}
    p=Info(token,12);try{Session=unchecked((uint)Marshal.ReadInt32(p));}finally{Marshal.FreeHGlobal(p);}
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
   p=Info(token,10);try{LogonLow=unchecked((uint)Marshal.ReadInt32(p,8));LogonHigh=unchecked((uint)Marshal.ReadInt32(p,12));}finally{Marshal.FreeHGlobal(p);}
    p=Info(token,12);try{Session=unchecked((uint)Marshal.ReadInt32(p));}finally{Marshal.FreeHGlobal(p);}
    p=Info(token,20);try{Elevated=Marshal.ReadInt32(p)!=0;}finally{Marshal.FreeHGlobal(p);}
   p=Info(token,25);try{Integrity=new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}finally{Marshal.FreeHGlobal(p);}
  }finally{CloseHandle(token);}
  if(!Alive)throw new InvalidOperationException("Process exited during sample");
 }
 public bool Alive {get {if(handle==IntPtr.Zero)return false;uint result=WaitForSingleObject(handle,0);if(result==0xffffffff)throw new Win32Exception();return result==258;}}
 public void Dispose(){if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
}

// This partial declaration contains only the selected-entry read-only boundary.
public sealed partial class StockProcessPin {
 [DllImport("rasapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
 static extern uint RasGetEntryPropertiesW(string phonebook,string entry,IntPtr data,ref uint size,IntPtr device,IntPtr deviceSize);
 static void ProfileRequire(bool value) { if(!value)throw new InvalidOperationException("Selected profile rejected"); }
 static uint ProfileD(byte[] b,int offset) {return BitConverter.ToUInt32(b,offset);}
 static string ProfileWide(byte[] b,int offset,int count) {
  int i=0;while(i<count && BitConverter.ToUInt16(b,offset+2*i)!=0)i++;
  ProfileRequire(i<count);return Encoding.Unicode.GetString(b,offset,i*2);
 }
 // Pure projection/predicate shared by production and synthetic tests. No native calls.
 public static Dictionary<string,object> SelectedProfileFromBytes(byte[] b) {
  ProfileRequire(b!=null && b.Length==StockProfileAbi.EntrySize && BitConverter.IsLittleEndian);
  ProfileRequire(ProfileD(b,StockProfileAbi.dwSize)==StockProfileAbi.EntrySize);
  var result=new Dictionary<string,object>(StringComparer.Ordinal);
  result.Add("schema","stock-selected-profile-v1");
  string[] keys={"size","options","alternateOffset","netProtocols","subEntries","type","encryption","customAuthKey","vpnStrategy","options2","options3","redialCount","imsConfig"};
  int[] offsets={StockProfileAbi.dwSize,StockProfileAbi.dwfOptions,StockProfileAbi.dwAlternateOffset,StockProfileAbi.dwfNetProtocols,StockProfileAbi.dwSubEntries,StockProfileAbi.dwType,StockProfileAbi.dwEncryptionType,StockProfileAbi.dwCustomAuthKey,StockProfileAbi.dwVpnStrategy,StockProfileAbi.dwfOptions2,StockProfileAbi.dwfOptions3,StockProfileAbi.dwRedialCount,StockProfileAbi.fIsImsConfig};
  for(int i=0;i<keys.Length;i++)result.Add(keys[i],ProfileD(b,offsets[i]));
  uint options=(uint)result["options"],options2=(uint)result["options2"],encryption=(uint)result["encryption"];
  ProfileRequire((uint)result["type"]==2 && (uint)result["vpnStrategy"]==7 && (uint)result["customAuthKey"]==26 && (options&0x20000)!=0 && (options&(0x40000u|0x80000u|0x08000000u|0x10000000u|0x20000000u|0x40000000u))==0);
  ProfileRequire((options2&(0x10u|0x100u|0x40000u|0x400000u|0x800000u|0x1000000u|0x4000000u|0x8000000u|0x10000000u|0x20000000u))==0 && (uint)result["redialCount"]==0 && (uint)result["options3"]==0);
  bool serverMatches=String.Equals(ProfileWide(b,StockProfileAbi.szLocalPhoneNumber,129),"ikev2.bimeron.test",StringComparison.OrdinalIgnoreCase);
  bool idiEmpty=ProfileWide(b,StockProfileAbi.szIDi,257)=="",idrEmpty=ProfileWide(b,StockProfileAbi.szIDr,257)=="";
  ProfileRequire(serverMatches && idiEmpty && idrEmpty);
  result.Add("serverMatches",serverMatches);result.Add("idiEmpty",idiEmpty);result.Add("idrEmpty",idrEmpty);
  ProfileRequire((options&0x10)!=0 && (options2&0x2000)!=0 && (uint)result["netProtocols"]==0xc && (encryption==1 || encryption==2));
  ProfileRequire((uint)result["alternateOffset"]==0 && (uint)result["subEntries"]<=1 && (uint)result["imsConfig"]==0 && (options&(0x40u|0x80u|0x100000u|0x80000000u|0x4000u))==0);
  string[] emptyKeys={"scriptEmpty","autodialDllEmpty","autodialFuncEmpty","customDialDllEmpty","prerequisitePbkEmpty","prerequisiteEntryEmpty"};
  int[] emptyOffsets={StockProfileAbi.szScript,StockProfileAbi.szAutodialDll,StockProfileAbi.szAutodialFunc,StockProfileAbi.szCustomDialDll,StockProfileAbi.szPrerequisitePbk,StockProfileAbi.szPrerequisiteEntry};
  for(int i=0;i<emptyKeys.Length;i++){bool empty=BitConverter.ToUInt16(b,emptyOffsets[i])==0;ProfileRequire(empty);result.Add(emptyKeys[i],empty);}
  return result;
 }
 public static Dictionary<string,object> ReadSelectedProfile(string phonebook) {
  ProfileRequire(Environment.Is64BitProcess && IntPtr.Size==8 && BitConverter.IsLittleEndian);
  string expected=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk");
  ProfileRequire(String.Equals(phonebook,expected,StringComparison.Ordinal) && File.Exists(phonebook));
  for(string current=phonebook;current!=null;current=System.IO.Path.GetDirectoryName(current)) {
   ProfileRequire((File.GetAttributes(current)&FileAttributes.ReparsePoint)==0);
  }
  // Bounded RASENTRY buffer, matching the launcher's supported layout. Device
  // information pointers are NULL. No credentials, EAP data or PBK bytes are read.
  int capacity=StockProfileAbi.EntrySize+65536;
  IntPtr data=Marshal.AllocHGlobal(capacity);
  byte[] zero=new byte[capacity];byte[] entry=new byte[StockProfileAbi.EntrySize];
  try {
   Marshal.Copy(zero,0,data,capacity);Marshal.WriteInt32(data,StockProfileAbi.EntrySize);
   uint size=(uint)capacity;
   uint error=RasGetEntryPropertiesW(phonebook,"Bimeron Step8",data,ref size,IntPtr.Zero,IntPtr.Zero);
   ProfileRequire(error==0 && size>=StockProfileAbi.EntrySize && size<=capacity);
   Marshal.Copy(data,entry,0,entry.Length);
   return SelectedProfileFromBytes(entry);
  } finally {Array.Clear(entry,0,entry.Length);Marshal.Copy(zero,0,data,capacity);Marshal.FreeHGlobal(data);}
 }
}

// Generated by inert SDK layout probe; Windows SDK 10.0.26100.0, x64, WINVER=0xA00.
internal static class StockProfileAbi {
internal const int EntrySize = 6724;
internal const int dwSize = 0;
internal const int dwfOptions = 4;
internal const int szLocalPhoneNumber = 38;
internal const int dwAlternateOffset = 296;
internal const int dwfNetProtocols = 324;
internal const int szScript = 332;
internal const int szAutodialDll = 852;
internal const int szAutodialFunc = 1372;
internal const int dwSubEntries = 3468;
internal const int dwType = 3496;
internal const int dwEncryptionType = 3500;
internal const int dwCustomAuthKey = 3504;
internal const int szCustomDialDll = 3524;
internal const int dwVpnStrategy = 4044;
internal const int dwfOptions2 = 4048;
internal const int dwfOptions3 = 4052;
internal const int szPrerequisitePbk = 4572;
internal const int szPrerequisiteEntry = 5092;
internal const int dwRedialCount = 5608;
internal const int szIDi = 5680;
internal const int szIDr = 6194;
internal const int fIsImsConfig = 6708;
internal const int TokenStatisticsSize = 56;
internal const int AuthenticationIdOffset = 8;
}
