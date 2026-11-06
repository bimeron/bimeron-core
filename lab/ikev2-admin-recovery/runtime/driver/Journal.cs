using System;
using System.IO;
using System.Text;
// Shared by the actual producer and every live snapshot reader.
public sealed class ProbeJournal : IDisposable {
    public static string LastReadOpenedUtc, LastReadClosedUtc;
    readonly FileStream stream;
    readonly UTF8Encoding utf8 = new UTF8Encoding(false, true);
    public ProbeJournal(string path) {
        stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
    }
    public void Record(string json) {
        if (json.Contains("\n") || json.Contains("\r")) throw new InvalidDataException("Multiline record");
        byte[] bytes = utf8.GetBytes(json + "\n");
        if (bytes.Length > 16384 || stream.Length + bytes.Length > 64L*1024*1024)
            throw new InvalidDataException("Journal bound");
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(true);
    }
    public void Dispose() { stream.Dispose(); }
    public static byte[] Snapshot(string path) { return Snapshot(path, 0); }
    public static byte[] Snapshot(string path, int testHoldMilliseconds) {
        if (testHoldMilliseconds < 0 || testHoldMilliseconds > 1000) throw new ArgumentOutOfRangeException("testHoldMilliseconds");
        using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
            LastReadOpenedUtc=DateTime.UtcNow.ToString("o");
            try {
            if (testHoldMilliseconds > 0) System.Threading.Thread.Sleep(testHoldMilliseconds);
            long length = input.Length;
            if (length > 64L*1024*1024) throw new InvalidDataException("Snapshot bound");
            byte[] data = new byte[(int)length];
            int offset = 0;
            while (offset < data.Length) {
                int n = input.Read(data, offset, data.Length-offset);
                if (n == 0) throw new EndOfStreamException("Journal truncated");
                offset += n;
            }
            return data;
            } finally { input.Dispose(); LastReadClosedUtc=DateTime.UtcNow.ToString("o"); }
        }
    }
}
