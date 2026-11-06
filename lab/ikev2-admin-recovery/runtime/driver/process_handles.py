"""Read-only retained Windows process identity handles; no mutation access."""
import ctypes
from ctypes import wintypes as W
class Handle:
 def _api(self):
  self.k=ctypes.WinDLL('kernel32',use_last_error=True);k=self.k
  k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
  k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
  k.CloseHandle.argtypes=[W.HANDLE]
  k.GetProcessTimes.argtypes=[W.HANDLE]+[ctypes.POINTER(ctypes.c_ulonglong)]*4
  k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,ctypes.POINTER(W.DWORD)]
 def __init__(self,pid):
  self._api();self.h=self.k.OpenProcess(0x1000|0x100000,False,pid)
  self._inspect(True)
 def _inspect(self,alive):
  k=self.k
  if not self.h:raise RuntimeError('Read-only process handle unavailable')
  try:
   times=[ctypes.c_ulonglong() for _ in range(4)]
   if not k.GetProcessTimes(self.h,*map(ctypes.byref,times)):raise RuntimeError('Process times unavailable')
   buf=ctypes.create_unicode_buffer(32768);size=W.DWORD(len(buf))
   if not k.QueryFullProcessImageNameW(self.h,0,buf,ctypes.byref(size)):raise RuntimeError('Process image unavailable')
   self.creation=times[0].value;self.exe=buf.value
   if alive:self.check()
  except BaseException:self.close();raise
 def check(self):
  if self.k.WaitForSingleObject(self.h,0)!=258:raise RuntimeError('Original process unavailable/signalled')
 def close(self):
  if self.h:self.k.CloseHandle(self.h);self.h=None

class ChildHandle(Handle):
 """Duplicate the original Popen handle; never reacquire a child by PID."""
 def __init__(self,child):
  self._api();k=self.k
  k.GetCurrentProcess.restype=W.HANDLE
  k.DuplicateHandle.argtypes=[W.HANDLE,W.HANDLE,W.HANDLE,ctypes.POINTER(W.HANDLE),W.DWORD,W.BOOL,W.DWORD]
  k.DuplicateHandle.restype=W.BOOL
  current=k.GetCurrentProcess();duplicate=W.HANDLE()
  if not k.DuplicateHandle(current,W.HANDLE(int(child._handle)),current,ctypes.byref(duplicate),0x1000|0x100000,False,0):
   raise RuntimeError('Original transport observation handle unavailable')
  self.h=duplicate.value;self._inspect(False)

def argv(command):
 if not command:raise RuntimeError('Command line unavailable')
 shell=ctypes.WinDLL('shell32');shell.CommandLineToArgvW.argtypes=[W.LPCWSTR,ctypes.POINTER(ctypes.c_int)];shell.CommandLineToArgvW.restype=ctypes.POINTER(W.LPWSTR)
 count=ctypes.c_int();p=shell.CommandLineToArgvW(command,ctypes.byref(count))
 if not p:raise RuntimeError('Command tokens unavailable')
 try:return [p[i] for i in range(count.value)]
 finally:
  k=ctypes.WinDLL('kernel32');k.LocalFree.argtypes=[ctypes.c_void_p];k.LocalFree(p)
