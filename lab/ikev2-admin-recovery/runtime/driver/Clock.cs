using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class LabClock {
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetSystemTimeAdjustment(out uint adjustment,out uint increment,out bool disabled);
 public static string Read() {
  uint a,i; bool d;if(!GetSystemTimeAdjustment(out a,out i,out d))throw new Exception("GetSystemTimeAdjustment failed");
  long smallest=long.MaxValue,previous=DateTime.UtcNow.Ticks; var sw=Stopwatch.StartNew();
  while(sw.ElapsedMilliseconds<50){long n=DateTime.UtcNow.Ticks;if(n>previous)smallest=Math.Min(smallest,n-previous);previous=n;}
  return "{\"utc\":"+(DateTime.UtcNow.Ticks-621355968000000000L)/10000000.0+",\"mono\":"+Stopwatch.GetTimestamp()/(double)Stopwatch.Frequency+",\"increment\":"+i/10000000.0+",\"adjustment\":"+a/10000000.0+",\"adjustmentDisabled\":"+d.ToString().ToLowerInvariant()+",\"observedMinimumStep\":"+(smallest==long.MaxValue?"null":(smallest/10000000.0).ToString(System.Globalization.CultureInfo.InvariantCulture))+"}";
 }
}
