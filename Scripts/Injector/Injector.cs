using System;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpMonoInjector;
public class Injector : IDisposable {
    const string mono_get_root_domain = "mono_get_root_domain";
    const string mono_thread_attach = "mono_thread_attach";
    const string mono_image_open_from_data = "mono_image_open_from_data";
    const string mono_assembly_load_from_full = "mono_assembly_load_from_full";
    const string mono_assembly_get_image = "mono_assembly_get_image";
    const string mono_class_from_name = "mono_class_from_name";
    const string mono_class_get_method_from_name = "mono_class_get_method_from_name";
    const string mono_runtime_invoke = "mono_runtime_invoke";
    const string mono_assembly_close = "mono_assembly_close";
    const string mono_image_strerror = "mono_image_strerror";
    const string mono_object_get_class = "mono_object_get_class";
    const string mono_class_get_name = "mono_class_get_name";
    const string mono_set_assemblies_path = "mono_set_assemblies_path";
    const string mono_assembly_setrootdir = "mono_assembly_setrootdir";
    const string mono_set_config_dir = "mono_set_config_dir";
    const string mono_jit_init = "mono_jit_init";
    const string il2cpp_thread_attach = "il2cpp_thread_attach";
    const string il2cpp_domain_get = "il2cpp_domain_get";

    Dictionary<string, IntPtr> Exports { get; } = new Dictionary<string, IntPtr> {
        { mono_get_root_domain, IntPtr.Zero },
        { il2cpp_domain_get, IntPtr.Zero },
        { mono_thread_attach, IntPtr.Zero },
        { il2cpp_thread_attach, IntPtr.Zero },
        { mono_image_open_from_data, IntPtr.Zero },
        { mono_assembly_load_from_full, IntPtr.Zero },
        { mono_assembly_get_image, IntPtr.Zero },
        { mono_class_from_name, IntPtr.Zero },
        { mono_class_get_method_from_name, IntPtr.Zero },
        { mono_runtime_invoke, IntPtr.Zero },
        { mono_assembly_close, IntPtr.Zero },
        { mono_image_strerror, IntPtr.Zero },
        { mono_object_get_class, IntPtr.Zero },
        { mono_set_assemblies_path, IntPtr.Zero },
        { mono_assembly_setrootdir, IntPtr.Zero },
        { mono_set_config_dir, IntPtr.Zero },
        { mono_jit_init, IntPtr.Zero },
        { mono_class_get_name, IntPtr.Zero }
    };

    Memory memory;

    IntPtr rootDomain;
    IntPtr _il2cppDomain;

    bool attach;
    bool _il2cppattach;

    readonly IntPtr handle;

    IntPtr mono;
    IntPtr _gameAssembly;

    String etcPath;

    public bool Is64Bit { get; set; }

    public Injector(string processName) : this(Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase))) { }
    public Injector(int processId) : this(Process.GetProcesses().FirstOrDefault(p => p.Id == processId)) { }


    public Injector(Process process) {
        this.etcPath = Path.GetDirectoryName(process.MainModule.FileName) + @"\" + Path.GetFileNameWithoutExtension(process.MainWindowTitle) + @"_Data\il2cpp_data\etc";

        if (process == null)
                        throw new InjectorException($"Bad process");
        if ((this.handle = Native.OpenProcess(ProcessAccessRights.PROCESS_ALL_ACCESS, false, process.Id)) == IntPtr.Zero)
                        throw new InjectorException("Failed to open process", new Win32Exception(Marshal.GetLastWin32Error()));
        #if DEBUG
        DllInjector.ShowConsole(this.handle);
        #endif

        this.Is64Bit = ProcessUtils.Is64BitProcess(this.handle);

        if (!ProcessUtils.GetMonoModule(this.handle, out this.mono))
        {
            var monoPath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            var monoDll = monoPath + @"\mono\mono-2.0-bdwgc.dll";
            /*if (!File.Exists(monoDll))
            {
                File.WriteAllBytes("mono-2.0-bdwgc.dl_", new WebClient().DownloadData("https://symbolserver.unity3d.com/mono-2.0-bdwgc.dll/5F36619D76c000/mono-2.0-bdwgc.dl_"));
                var cab = new Microsoft.Deployment.Compression.Cab.CabInfo("mono-2.0-bdwgc.dl_");
                cab.UnpackFile("mono-2.0-bdwgc.dll", monoDll);
                File.Delete("mono-2.0-bdwgc.dl_");
            }*/
            DllInjector.Inject(this.handle, monoDll);
            if (!ProcessUtils.GetMonoModule(this.handle, out this.mono))
                throw new InjectorException("Failed to find mono.dll in the target process");
        }

        if (!ProcessUtils.GetGameAssembly(this.handle, out this._gameAssembly))
            throw new InjectorException("Failed to find GameAssembly.dll in the target process");

        this.memory = new Memory(this.handle);
    }

    // public Injector(int processId) {
    //     Process process = Process.GetProcesses().FirstOrDefault(p => p.Id == processId);

    //     if (process == null)
    //         throw new InjectorException($"Could not find a process with the id {processId}");

    //     if ((_handle = Native.OpenProcess(ProcessAccessRights.PROCESS_ALL_ACCESS, false, process.Id)) == IntPtr.Zero)
    //         throw new InjectorException("Failed to open process", new Win32Exception(Marshal.GetLastWin32Error()));

    //     Is64Bit = ProcessUtils.Is64BitProcess(_handle);

    //     if (!ProcessUtils.GetMonoModule(_handle, out _mono))
    //         throw new InjectorException("Failed to find mono.dll in the target process");

    //     _memory = new Memory(_handle);
    // }

    public Injector(IntPtr processHandle, IntPtr monoModule) {
        if ((this.handle = processHandle) == IntPtr.Zero) throw new ArgumentException("Argument cannot be zero", nameof(processHandle));
        if ((this.mono = monoModule) == IntPtr.Zero) throw new ArgumentException("Argument cannot be zero", nameof(monoModule));

        this.Is64Bit = ProcessUtils.Is64BitProcess(this.handle);
        this.memory = new Memory(this.handle);
    }

    public void Dispose() {
        this.memory.Dispose();
        _ = Native.CloseHandle(this.handle);
    }

    void ObtainMonoExports() {
        foreach (ExportedFunction ef in ProcessUtils.GetExportedFunctions(this.handle, this.mono)) {
            if (this.Exports.ContainsKey(ef.name)) this.Exports[ef.name] = ef.address;
        }

        foreach (ExportedFunction ef in ProcessUtils.GetExportedFunctions(this.handle, this._gameAssembly))
            if (this.Exports.ContainsKey(ef.name))
                this.Exports[ef.name] = ef.address;

        foreach (KeyValuePair<string, IntPtr> kvp in this.Exports) {
            if (kvp.Value == IntPtr.Zero) {
                throw new InjectorException($"Failed to obtain the address of {kvp.Key}()");
            }
        }
    }

    public IntPtr Inject(byte[] rawAssembly, string @namespace, string className, string methodName) {
        if (rawAssembly == null) throw new ArgumentNullException(nameof(rawAssembly));
        if (rawAssembly.Length == 0) throw new ArgumentException($"{nameof(rawAssembly)} cannot be empty", nameof(rawAssembly));
        if (className == null) throw new ArgumentNullException(nameof(className));
        if (methodName == null) throw new ArgumentNullException(nameof(methodName));

        IntPtr rawImage, assembly, image, @class, method;

        this.ObtainMonoExports();
        this.rootDomain = this.GetRootDomain();
        this._il2cppDomain = GetIl2CppRootDomain();
        rawImage = this.OpenImageFromData(rawAssembly);
        this.attach = true;
        assembly = this.OpenAssemblyFromImage(rawImage);
        image = this.GetImageFromAssembly(assembly);
        @class = this.GetClassFromName(image, @namespace, className);
        method = this.GetMethodFromName(@class, methodName);
        this._il2cppattach = true;
        this.RuntimeInvoke(method);
        return assembly;
    }

    public void Eject(IntPtr assembly, string @namespace, string className, string methodName) {
        if (assembly == IntPtr.Zero) throw new ArgumentException($"{nameof(assembly)} cannot be zero", nameof(assembly));
        if (className == null) throw new ArgumentNullException(nameof(className));
        if (methodName == null) throw new ArgumentNullException(nameof(methodName));

        IntPtr image, @class, method;

        this.ObtainMonoExports();
        this.rootDomain = this.GetRootDomain();
        this.attach = true;
        image = this.GetImageFromAssembly(assembly);
        @class = this.GetClassFromName(image, @namespace, className);
        method = this.GetMethodFromName(@class, methodName);
        this.RuntimeInvoke(method);
        this.CloseAssembly(assembly);
    }

    static void ThrowIfNull(IntPtr ptr, string methodName) {
        if (ptr != IntPtr.Zero) return;
        throw new InjectorException($"{methodName}() returned NULL");
    }

    IntPtr GetRootDomain() {
        IntPtr rootDomain = this.Execute(this.Exports[mono_get_root_domain]);
        var qq = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        if (rootDomain == IntPtr.Zero)
            SetupMono(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + @"\Managed", Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + @"", etcPath);
        rootDomain = Execute(Exports[mono_get_root_domain]);
        ThrowIfNull(rootDomain, mono_get_root_domain);
        return rootDomain;
    }

    void SetupMono(string assembliesPath, string rootpath, string configDir)
    {
        this.Execute(this.Exports[mono_set_assemblies_path], this.memory.AllocateAndWrite(assembliesPath), IntPtr.Zero);
        this.Execute(this.Exports[mono_assembly_setrootdir], this.memory.AllocateAndWrite(rootpath), IntPtr.Zero);
        this.Execute(this.Exports[mono_set_config_dir], this.memory.AllocateAndWrite(configDir), IntPtr.Zero);
        this.Execute(this.Exports[mono_jit_init], this.memory.AllocateAndWrite("MonoLoader"), IntPtr.Zero);
    }

    IntPtr GetIl2CppRootDomain()
    {
        IntPtr rootDomain = this.Execute(this.Exports[il2cpp_domain_get]);
        ThrowIfNull(rootDomain, il2cpp_domain_get);
        return rootDomain;
    }

    IntPtr OpenImageFromData(byte[] assembly) {
        IntPtr statusPtr = this.memory.Allocate(4);
        IntPtr rawImage = this.Execute(this.Exports[mono_image_open_from_data], this.memory.AllocateAndWrite(assembly), (IntPtr)assembly.Length, (IntPtr)1, statusPtr);

        MonoImageOpenStatus status = (MonoImageOpenStatus)this.memory.ReadInt(statusPtr);

        if (status != MonoImageOpenStatus.MONO_IMAGE_OK) {
            IntPtr messagePtr = this.Execute(this.Exports[mono_image_strerror], (IntPtr)status);
            string message = this.memory.ReadString(messagePtr, 256, Encoding.UTF8);
            throw new InjectorException($"{mono_image_open_from_data}() failed: {message}");
        }

        return rawImage;
    }

    IntPtr OpenAssemblyFromImage(IntPtr image) {
        IntPtr statusPtr = this.memory.Allocate(4);
        IntPtr assembly = this.Execute(this.Exports[mono_assembly_load_from_full], image, this.memory.AllocateAndWrite(new byte[1]), statusPtr, IntPtr.Zero);

        MonoImageOpenStatus status = (MonoImageOpenStatus)this.memory.ReadInt(statusPtr);

        if (status != MonoImageOpenStatus.MONO_IMAGE_OK) {
            IntPtr messagePtr = this.Execute(this.Exports[mono_image_strerror], (IntPtr)status);
            string message = this.memory.ReadString(messagePtr, 256, Encoding.UTF8);
            throw new InjectorException($"{mono_assembly_load_from_full}() failed: {message}");
        }

        return assembly;
    }

    IntPtr GetImageFromAssembly(IntPtr assembly) {
        IntPtr image = this.Execute(this.Exports[mono_assembly_get_image], assembly);
        ThrowIfNull(image, mono_assembly_get_image);
        return image;
    }

    IntPtr GetClassFromName(IntPtr image, string @namespace, string className) {
        IntPtr @class = this.Execute(this.Exports[mono_class_from_name], image, this.memory.AllocateAndWrite(@namespace), this.memory.AllocateAndWrite(className));
        ThrowIfNull(@class, mono_class_from_name);
        return @class;
    }

    IntPtr GetMethodFromName(IntPtr @class, string methodName) {
        IntPtr method = this.Execute(this.Exports[mono_class_get_method_from_name], @class, this.memory.AllocateAndWrite(methodName), IntPtr.Zero);
        ThrowIfNull(method, mono_class_get_method_from_name);
        return method;
    }

    string GetClassName(IntPtr monoObject) {
        IntPtr @class = this.Execute(this.Exports[mono_object_get_class], monoObject);
        ThrowIfNull(@class, mono_object_get_class);
        IntPtr className = this.Execute(this.Exports[mono_class_get_name], @class);
        ThrowIfNull(className, mono_class_get_name);
        return this.memory.ReadString(className, 256, Encoding.UTF8);
    }

    string ReadMonoString(IntPtr monoString) {
        int len = this.memory.ReadInt(monoString + (this.Is64Bit ? 0x10 : 0x8));
        return this.memory.ReadUnicodeString(monoString + (this.Is64Bit ? 0x14 : 0xC), len * 2);
    }

    void RuntimeInvoke(IntPtr method) {
        IntPtr excPtr = this.Is64Bit ? this.memory.AllocateAndWrite((long)0) : this.memory.AllocateAndWrite(0);
        _ = this.Execute(this.Exports[mono_runtime_invoke], method, IntPtr.Zero, IntPtr.Zero, excPtr);

        IntPtr exc = (IntPtr)this.memory.ReadLong(excPtr);

        if (exc != IntPtr.Zero) {
            string className = this.GetClassName(exc);
            string message = this.ReadMonoString((IntPtr)this.memory.ReadLong(exc + (this.Is64Bit ? 0x20 : 0x10)));
            throw new InjectorException($"The managed method threw an exception: ({className}) {message}");
        }
    }

    void CloseAssembly(IntPtr assembly) {
        IntPtr result = this.Execute(this.Exports[mono_assembly_close], assembly);
        ThrowIfNull(result, mono_assembly_close);
    }

    IntPtr Execute(IntPtr address, params IntPtr[] args) {
        IntPtr retValPtr = this.Is64Bit ? this.memory.AllocateAndWrite((long)0) : this.memory.AllocateAndWrite(0);

        byte[] code = this.Assemble(address, retValPtr, args);
        IntPtr alloc = this.memory.AllocateAndWrite(code);

        IntPtr thread = Native.CreateRemoteThread(this.handle, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, out _);

        if (thread == IntPtr.Zero)
            throw new InjectorException("Failed to create a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

        WaitResult result = Native.WaitForSingleObject(thread, -1);

        if (result == WaitResult.WAIT_FAILED)
            throw new InjectorException("Failed to wait for a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

        IntPtr ret = this.Is64Bit ? (IntPtr)this.memory.ReadLong(retValPtr) : (IntPtr)this.memory.ReadInt(retValPtr);

        return ret == (IntPtr)0x00000000C0000005
            ? throw new InjectorException($"An access violation occurred while executing {this.Exports.First(e => e.Value == address).Key}()")
            : ret;
    }

    byte[] Assemble(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args) => this.Is64Bit ? this.Assemble64(functionPtr, retValPtr, args) : this.Assemble86(functionPtr, retValPtr, args);

    byte[] Assemble86(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args) {
        Assembler asm = new();

        if (this.attach) {
            asm.Push(this.rootDomain);
            asm.MovEax(this.Exports[mono_thread_attach]);
            asm.CallEax();
            asm.AddEsp(4);
        }

        for (int i = args.Length - 1; i >= 0; i--) asm.Push(args[i]);

        asm.MovEax(functionPtr);
        asm.CallEax();
        asm.AddEsp((byte)(args.Length * 4));
        asm.MovEaxTo(retValPtr);
        asm.Return();

        return asm.ToByteArray();
    }

    byte[] Assemble64(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args) {
        Assembler asm = new();

        asm.SubRsp(40);

        if (this.attach) {
            asm.MovRax(this.Exports[mono_thread_attach]);
            asm.MovRcx(this.rootDomain);
            asm.CallRax();
        }
        if (this._il2cppattach)
        {
            asm.MovRax(this.Exports[il2cpp_thread_attach]);
            asm.MovRcx(this._il2cppDomain);
            asm.CallRax();
        }

        asm.MovRax(functionPtr);

        for (int i = 0; i < args.Length; i++) {
            switch (i) {
                case 0:
                    asm.MovRcx(args[i]);
                    break;
                case 1:
                    asm.MovRdx(args[i]);
                    break;
                case 2:
                    asm.MovR8(args[i]);
                    break;
                case 3:
                    asm.MovR9(args[i]);
                    break;
            }
        }

        asm.CallRax();
        asm.AddRsp(40);
        asm.MovRaxTo(retValPtr);
        asm.Return();

        return asm.ToByteArray();
    }

    public class DllInjector
    {
        [DllImport("kernel32")] static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static void Inject(IntPtr procHandle, String dllName)
        {
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), 0x3000, 4);
            WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf<char>()), out UIntPtr bytesWritten);
            var t = CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
            Native.WaitForSingleObject(t, -1);
        }
        public static void ShowConsole(IntPtr procHandle)
        {
            IntPtr allocConsoleAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "AllocConsole");
            var t = CreateRemoteThread(procHandle, IntPtr.Zero, 0, allocConsoleAddr, IntPtr.Zero, 0, IntPtr.Zero);
            Native.WaitForSingleObject(t, -1);
        }
    }
}
