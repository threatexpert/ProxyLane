// Exercise CLR startup, initialized Winsock hooks, and a managed child of the other bitness.
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

class ManagedStartupProbe
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr GetModuleHandle(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern uint GetModuleFileName(IntPtr module, StringBuilder path, int size);

    static int Main(string[] args)
    {
        if (args.Length != 2) return 2;
        try
        {
            string directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string dll = "ProxyLaneHook" + (IntPtr.Size * 8) + ".dll";
            IntPtr module = GetModuleHandle(dll);
            StringBuilder loaded = new StringBuilder(1024);
            if (module == IntPtr.Zero || GetModuleFileName(module, loaded, loaded.Capacity) == 0 ||
                !String.Equals(loaded.ToString(), Path.Combine(directory, dll), StringComparison.OrdinalIgnoreCase))
                throw new Exception("Expected test Hook DLL is not loaded: " + loaded);

            using (TcpClient client = new TcpClient())
            {
                IAsyncResult pending = client.BeginConnect("203.0.113.10", 39093, null, null);
                using (var completion = pending.AsyncWaitHandle)
                {
                    if (!completion.WaitOne(10000)) throw new Exception("Proxy connection timed out");
                    client.EndConnect(pending);
                }
                client.ReceiveTimeout = client.SendTimeout = 10000;
                NetworkStream stream = client.GetStream();
                byte[] ping = Encoding.ASCII.GetBytes("PING"), pong = new byte[4];
                stream.Write(ping, 0, ping.Length);
                int count = 0;
                while (count < pong.Length)
                {
                    int received = stream.Read(pong, count, pong.Length - count);
                    if (received == 0) throw new Exception("Unexpected EOF");
                    count += received;
                }
                if (Encoding.ASCII.GetString(pong) != "PONG") throw new Exception("Invalid proxy reply");
            }

            if (args[1] != "leaf")
            {
                ProcessStartInfo start = new ProcessStartInfo(Path.Combine(directory, args[1]),
                    "\"" + args[0] + ".child\" leaf");
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                using (Process child = Process.Start(start))
                {
                    if (!child.WaitForExit(20000))
                    {
                        child.Kill();
                        throw new Exception("Managed child timed out");
                    }
                    if (child.ExitCode != 0) throw new Exception("Managed child failed: " + child.ExitCode);
                }
            }
            File.WriteAllText(args[0], "PASS bits=" + (IntPtr.Size * 8) + " hook=" + loaded + " network=1");
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(args[0], error.ToString());
            return 1;
        }
    }
}
