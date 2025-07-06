# Shellcode Loader (Windows, XOR-Decoded, Fiber Execution)

> ⚠️ **Disclaimer**: This project is intended strictly for **educational and research purposes**. Do **not** use this tool in unauthorized environments. Executing or distributing malicious software is illegal and unethical. Always operate within legal boundaries and obtain proper consent.

---

## 🧠 Description

This project demonstrates a **Windows shellcode loader** written in C that implements multiple evasion and persistence techniques. The loader is designed to execute encoded shellcode in-memory using the Windows **Fiber API** and includes:

- ❌ Basic **anti-debugging** using `IsDebuggerPresent`
- 🧪 **VM detection** by checking for common virtualization-related processes
- 💾 **Shellcode decoding** using XOR decryption
- 💨 **In-memory shellcode execution** with `VirtualAlloc`, `memcpy`, and `VirtualProtect`
- 🧵 **Execution via fiber context** (`ConvertThreadToFiber`, `CreateFiber`, `SwitchToFiber`)
- 🔁 **Persistence** through registry key injection (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)

---

## 🔍 How It Works

1. **Anti-Debugging / Anti-VM**:
   - Checks if the process is being debugged using `IsDebuggerPresent`.
   - Scans for common VM-related processes like `vmtoolsd.exe`, `vboxservice.exe`, etc.

2. **Shellcode Loader**:
   - Decodes the shellcode with a simple XOR key.
   - Allocates executable memory (`VirtualAlloc`) and copies decoded shellcode to it.
   - Modifies memory protections to allow execution (`VirtualProtect`).
   - Executes shellcode using Windows **fibers** for stealth.

3. **Persistence**:
   - Adds the current executable to the Windows Registry Run key for execution at user login.

---

## ⚙️ Usage

> This tool is for analysis and lab environments only. Do **not** compile or execute on production systems.

1. Encode your shellcode using XOR with the same key (`0x5F` by default).
2. Replace `unsigned char shellCode[] = {};` with your encoded shellcode bytes.
3. Compile using MinGW or Visual Studio:

```bash
gcc shellcode_loader.c -o loader.exe -luser32 -ladvapi32
