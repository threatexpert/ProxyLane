// A disposable packaged Win32 application, its installer, and child processes.
using System;
using System.IO;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class AppsFolderProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref STARTUPINFO si,out PROCESS_INFORMATION pi);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO info);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr token,uint flags,uint disableCount,IntPtr disabled,uint deleteCount,IntPtr deleted,uint restrictCount,IntPtr restricted,out IntPtr result);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr token,string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref STARTUPINFO si,out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder path,ref uint size);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct STARTUPINFO {
        public uint cb; public string reserved,desktop,title; public uint x,y,cx,cy,xc,yc,fill,flags;
        public ushort show,reserved2; public IntPtr reservedBytes,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr process,thread; public uint pid,tid; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SHELLEXECUTEINFO {
        public uint cb,mask; public IntPtr window; public string verb,file,parameters,directory;
        public int show; public IntPtr instance,idList; public string className;
        public IntPtr classKey; public uint hotKey; public IntPtr icon,process;
    }
    static string Root=AppDomain.CurrentDomain.BaseDirectory;
    static void Require(bool value,string text) { if(!value) throw new Exception(text+" win32="+Marshal.GetLastWin32Error()); }
    static bool Hooked() { return GetModuleHandle("ProxyLaneHook"+(IntPtr.Size*8)+".dll")!=IntPtr.Zero; }
    static void Until(Func<bool> check,int ms,string name) { Stopwatch w=Stopwatch.StartNew(); while(!check()) { if(w.ElapsedMilliseconds>ms) throw new Exception("Timeout: "+name); Thread.Sleep(25); } }
    static void Traffic() {
        using(TcpClient client=new TcpClient()) {
            IAsyncResult pending=client.BeginConnect("203.0.113.10",39093,null,null);
            Require(pending.AsyncWaitHandle.WaitOne(10000),"connect timeout"); client.EndConnect(pending);
            client.ReceiveTimeout=client.SendTimeout=10000;
            NetworkStream stream=client.GetStream(); byte[] ping=Encoding.ASCII.GetBytes("PING"),pong=new byte[4]; stream.Write(ping,0,4);
            int count=0; while(count<4) { int n=stream.Read(pong,count,4-count); Require(n>0,"EOF");count+=n; }
            Require(Encoding.ASCII.GetString(pong)=="PONG","proxy reply");
        }
    }
    static int Main(string[] args) {
        string report=Path.Combine(Root,"app.done");
        try {
            if(args.Length>0 && args[0]=="hold") { Thread.Sleep(60000); return 0; }
            if(args.Length>0 && args[0]=="installer") {
                report=args[2]; Require(Hooked(),"installer not hooked");
                bool suspended=args[3]=="suspended",closeEarly=args[3]=="close";
                string explorer=Path.Combine(Environment.GetEnvironmentVariable("windir"),"explorer.exe");
                STARTUPINFO si=new STARTUPINFO(); si.cb=(uint)Marshal.SizeOf(si); PROCESS_INFORMATION pi=new PROCESS_INFORMATION();
                if(args[3]=="shell") {
                    SHELLEXECUTEINFO se=new SHELLEXECUTEINFO(); se.cb=(uint)Marshal.SizeOf(se);
                    se.mask=0x40|0x100|0x400; se.verb="open"; se.file=explorer;
                    se.parameters="shell:AppsFolder\\"+args[1]; se.show=0;
                    Require(ShellExecuteEx(ref se) && se.process!=IntPtr.Zero,"ShellExecuteEx launcher");
                    pi.process=se.process;
                } else {
                    bool bare=args[3]=="bare",newConsole=args[3]=="newconsole";
                    string command=bare?"explorer.exe shell:AppsFolder\\"+args[1]:"\""+explorer+"\" \"shell:AppsFolder\\"+args[1]+"\"";
                    if(args[3]=="token") {
                        IntPtr own=IntPtr.Zero,restricted=IntPtr.Zero;
                        try {
                            Require(OpenProcessToken(Process.GetCurrentProcess().Handle,0xB,out own),"open own token");
                            Require(CreateRestrictedToken(own,1,0,IntPtr.Zero,0,IntPtr.Zero,0,IntPtr.Zero,out restricted),"restrict same-user token");
                            Require(CreateProcessAsUser(restricted,explorer,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,0,IntPtr.Zero,null,ref si,out pi),"same-user token launcher");
                        } finally {
                            if(restricted!=IntPtr.Zero) CloseHandle(restricted);
                            if(own!=IntPtr.Zero) CloseHandle(own);
                        }
                    } else Require(CreateProcess(bare?null:explorer,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,suspended?4u:(newConsole?0x210u:0u),IntPtr.Zero,null,ref si,out pi),"create launcher");
                }
                try {
                    StringBuilder image=new StringBuilder(1024); uint size=1024;
                    Require(QueryFullProcessImageName(pi.process,0,image,ref size),"query helper image");
                    Require(Path.GetFileName(image.ToString()).StartsWith("ProxyLane",StringComparison.OrdinalIgnoreCase),"not replaced: "+image);
                    if(closeEarly) {
                        CloseHandle(pi.thread); CloseHandle(pi.process);
                        pi.thread=pi.process=IntPtr.Zero;
                    }
                    if(suspended) {
                        Thread.Sleep(700); Require(!File.Exists(Path.Combine(Root,"app.started")),"activated before resume");
                        Require(ResumeThread(pi.thread)==1,"resume caller suspension");
                    }
                    if(!closeEarly) {
                        Require(WaitForSingleObject(pi.process,30000)==0,"helper wait"); uint code;
                        Require(GetExitCodeProcess(pi.process,out code) && code==0,"helper failed");
                        Require(!File.Exists(Path.Combine(Root,"app.done")),"helper waited for final app exit");
                    }
                    File.WriteAllText(Path.Combine(Root,"app.go"),"go");
                    Until(()=>File.Exists(Path.Combine(Root,"app.done")),30000,"app/child completion");
                    Require(File.ReadAllText(Path.Combine(Root,"app.done")).StartsWith("PASS"),"app failed");
                    File.WriteAllText(report,"PASS installer="+(IntPtr.Size*8)+" mode="+args[3]+" helper="+image);
                } finally {
                    if(pi.thread!=IntPtr.Zero) CloseHandle(pi.thread);
                    if(pi.process!=IntPtr.Zero) CloseHandle(pi.process);
                }
            } else if(args.Length>0 && args[0]=="leaf") {
                report=args[1]; Require(Hooked(),"child not hooked"); Traffic();File.WriteAllText(report,"PASS child="+(IntPtr.Size*8)+" proxy=1");
            } else {
                File.AppendAllText(Path.Combine(Root,"app.activations"),Process.GetCurrentProcess().Id+"\n");
                File.WriteAllText(Path.Combine(Root,"app.started"),Process.GetCurrentProcess().Id.ToString());
                Until(()=>Hooked(),15000,"package Hook load");
                Until(()=>File.Exists(Path.Combine(Root,"app.go")),35000,"installer release");
                Traffic();
                foreach(int bits in new int[]{32,64}) {
                    string childReport=Path.Combine(Root,"child"+bits+".done");
                    ProcessStartInfo start=new ProcessStartInfo(Path.Combine(Root,"probe"+bits+".exe"),"leaf \""+childReport+"\"");
                    start.UseShellExecute=false;start.CreateNoWindow=true;
                    using(Process child=Process.Start(start)) Require(child.WaitForExit(20000) && child.ExitCode==0,"child failed");
                }
                File.WriteAllText(report,"PASS package="+(IntPtr.Size*8)+" proxy=1 children=32,64");
            }
            return 0;
        } catch(Exception e) { File.WriteAllText(report,e.ToString());return 1; }
    }
}
