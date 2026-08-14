# DLL Injection with Driver Setup

This project is a tool used for performing **DLL injection (injecting code)** into a specific game or application process (such as `cod.exe`). The application first loads a **driver**, then interacts with the target process and injects the specified **DLL file**.

## Requirements
- Windows operating system
- Visual Studio 2022
- A `target.exe` process (game or application)
- `dummy.dll` (or another DLL file) for injection

## Compilation

- Download the project to your computer.
- Extract the project to a folder.
- Open the Solution File (`.sln`)
- From the **Build** menu, select **Build Solution** (`Ctrl + Shift + B`).

## Usage

- After compiling the project, copy the DLL file you want to inject into the same directory where the compiled `.exe` file is located.

- By default, the name of the DLL is `dummy.dll`. You can change this in the code if needed.

    ```cpp
    inject_codes inject_status = face_injector_v4(process_id, xor_w(L"dummy.dll"));
    ```

- By default, the DLL will attempt to inject into the `cod.exe` program.

    ```cpp
    DWORD process_id = get_process_id_by_name(xor_w(L"cod.exe"));
    ```

**DLL Injection:**  
   The specified `dummy.dll` file will be attempted to inject into the target process. Errors encountered during the injection process will be reported to the user.

### Error Codes
The error codes encountered during injection are:

- **Process Error:** Target process not found.
- **Invalid DLL:** Invalid DLL file.
- **Invalid PE Header:** Invalid header in the DLL file.
- **Allocation Error:** Memory allocation error.
- **Relocation Error:** Error in relocating the DLL.
- **Resolve Imports Error:** Error resolving external libraries of the DLL.
- **Inject Success:** DLL successfully injected.

### Example Outputs

After a successful injection:

```
inject success!
```

After an error:

```
error driver load
```

## Disclaimer

This project is for educational purposes only and may violate the terms of use of any software or game. Use at your own risk.

## Contribution

If you would like to contribute to this project, please leave a star on the repository.

## License

This project is licensed under the [MIT License](LICENSE). You are free to use and modify it as long as you comply with the license terms.