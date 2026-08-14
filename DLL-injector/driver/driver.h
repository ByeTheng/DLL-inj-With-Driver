#include "dispath/defines.h"

DWORD driver_pid = 0;
ULONG build_number = 0;

int64_t last_error = 0;

uint64_t(*nt_gdi_poly_poly_draw)(uint64_t, void*, void*, uint32_t, int32_t) = nullptr;

#define xor_status_success xor_int(0)
#define xor_status_unsuccessful xor_int(3221225473)

void attach_driver(DWORD pid)
{
	driver_pid = pid;
}

bool driver_setup()
{
	build_number = *(ULONG*)(xor_int(2147353184));

	if (build_number < xor_int(19041))
		return false;

	auto win32u = GetModuleHandleW(xor_w(L"win32u.dll"));
	if (!win32u)
	{
		win32u = LoadLibraryW(xor_w(L"win32u.dll"));
		if (!win32u)
			return false;
	}

	auto addr = GetProcAddress(win32u, xor_a("NtGdiPolyPolyDraw"));
	if (!addr)
		return false;

	*(PVOID*)&nt_gdi_poly_poly_draw = addr;

	return true;
}

int run_pe(LPPROCESS_INFORMATION lpPI, LPSTARTUPINFO lpSI, LPVOID lpImage, LPWSTR wszArgs, SIZE_T szArgs)
{
    WCHAR wszFilePath[MAX_PATH];
    if (!GetModuleFileName(
        NULL,
        wszFilePath,
        sizeof wszFilePath
    ))
    {
        return -1;
    }
    WCHAR wszArgsBuffer[MAX_PATH + 2048];
    ZeroMemory(wszArgsBuffer, sizeof wszArgsBuffer);
    SIZE_T length = wcslen(wszFilePath);
    memcpy(
        wszArgsBuffer,
        wszFilePath,
        length * sizeof(WCHAR)
    );
    wszArgsBuffer[length] = ' ';
    memcpy(
        wszArgsBuffer + length + 1,
        wszArgs,
        szArgs
    );

    PIMAGE_DOS_HEADER lpDOSHeader =
        reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
    PIMAGE_NT_HEADERS lpNTHeader =
        reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew
            );
    if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return -2;
    }

    if (!CreateProcess(
        NULL,
        wszArgsBuffer,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        lpSI,
        lpPI
    ))
    {
        return -3;
    }

    CONTEXT stCtx;
    ZeroMemory(&stCtx, sizeof stCtx);
    stCtx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(lpPI->hThread, &stCtx))
    {
        TerminateProcess(
            lpPI->hProcess,
            -4
        );
        return -4;
    }

    LPVOID lpImageBase = VirtualAllocEx(
        lpPI->hProcess,
        reinterpret_cast<LPVOID>(lpNTHeader->OptionalHeader.ImageBase),
        lpNTHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (lpImageBase == NULL)
    {
        TerminateProcess(
            lpPI->hProcess,
            -5
        );
        return -5;
    }

    if (!WriteProcessMemory(
        lpPI->hProcess,
        lpImageBase,
        lpImage,
        lpNTHeader->OptionalHeader.SizeOfHeaders,
        NULL
    ))
    {
        TerminateProcess(
            lpPI->hProcess,
            -6
        );
        return -6;
    }

    for (
        SIZE_T iSection = 0;
        iSection < lpNTHeader->FileHeader.NumberOfSections;
        ++iSection
        )
    {
        PIMAGE_SECTION_HEADER stSectionHeader =
            reinterpret_cast<PIMAGE_SECTION_HEADER>(
                reinterpret_cast<DWORD64>(lpImage) +
                lpDOSHeader->e_lfanew +
                sizeof(IMAGE_NT_HEADERS64) +
                sizeof(IMAGE_SECTION_HEADER) * iSection
                );

        if (!WriteProcessMemory(
            lpPI->hProcess,
            reinterpret_cast<LPVOID>(
                reinterpret_cast<DWORD64>(lpImageBase) +
                stSectionHeader->VirtualAddress
                ),
            reinterpret_cast<LPVOID>(
                reinterpret_cast<DWORD64>(lpImage) +
                stSectionHeader->PointerToRawData
                ),
            stSectionHeader->SizeOfRawData,
            NULL
        ))
        {
            TerminateProcess(
                lpPI->hProcess,
                -7
            );
            return -7;
        }
    }

    if (!WriteProcessMemory(
        lpPI->hProcess,
        reinterpret_cast<LPVOID>(
            stCtx.Rdx + sizeof(LPVOID) * 2
            ),
        &lpImageBase,
        sizeof(LPVOID),
        NULL
    ))
    {
        TerminateProcess(
            lpPI->hProcess,
            -8
        );
        return -8;
    }

    stCtx.Rcx = reinterpret_cast<DWORD64>(lpImageBase) +
        lpNTHeader->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(
        lpPI->hThread,
        &stCtx
    ))
    {
        TerminateProcess(
            lpPI->hProcess,
            -9
        );
        return -9;
    }

    if (!ResumeThread(lpPI->hThread))
    {
        TerminateProcess(
            lpPI->hProcess,
            -10
        );
        return -10;
    }

    return 0;
}

void mmap_driver()
{
    DWORD dwRet = 0;

    PROCESS_INFORMATION stPI;
    ZeroMemory(&stPI, sizeof stPI);

    STARTUPINFO stSI;
    ZeroMemory(&stSI, sizeof stSI);
    WCHAR szArgs[] = L"";

    if (!run_pe(&stPI, &stSI, reinterpret_cast<LPVOID>(loader_array), szArgs, sizeof szArgs))
    {
        WaitForSingleObject(stPI.hProcess, INFINITE);

        GetExitCodeProcess(stPI.hProcess, &dwRet);

        CloseHandle(stPI.hThread);
        CloseHandle(stPI.hProcess);
    }
}

bool send_message(uint64_t comm_code, operation_data* req)
{
	nt_gdi_poly_poly_draw(comm_code, req, (PVOID)(xor_int(9364)), sizeof(operation_data), xor_int(2));

	return true;
}

int64_t get_last_error()
{
	return last_error;
}

void set_last_error(int64_t error)
{
	last_error = error;
}

bool is_driver_load_ex()
{
	operation_data req = {};

	if (!send_message(comm_code::is_driver_load, &req))
		return false;

	set_last_error(req.status_code);

	return (req.load_code == xor_int(265431));
}

void* process_base_address_ex()
{
	operation_data req = {};

	req.pba_pid = driver_pid;

	if (!send_message(comm_code::process_base_address, &req))
		return 0;

	set_last_error(req.status_code);

	return req.pba_out_address;
}

void* alloc_kernel_memory_ex(ULONG size)
{
	operation_data req = {};

	req.akm_size = size;
	req.akm_pid = driver_pid;

	if (!send_message(comm_code::alloc_kernel_memory, &req))
		return 0;

	set_last_error(req.status_code);

	return req.akm_address;
}

bool read_memory_ex(PVOID base, PVOID buffer, DWORD size, DWORD* return_size = 0)
{
	operation_data req = {};

	if (!driver_pid || !base || !buffer || !size)
		return false;

	req.cm_pid = driver_pid;
	req.cm_address = base;
	req.cm_buffer = buffer;
	req.cm_size = size;
	req.cm_write = false;

	if (!send_message(comm_code::copy_memory, &req))
		return false;

	if (return_size)
		*return_size = req.cm_return_size;

	return true;
}

bool write_memory_ex(PVOID base, PVOID buffer, DWORD size, DWORD* return_size = 0)
{
	operation_data req = {};

	if (!driver_pid || !base || !buffer || !size)
		return false;

	req.cm_pid = driver_pid;
	req.cm_address = base;
	req.cm_buffer = buffer;
	req.cm_size = size;
	req.cm_write = true;

	if (!send_message(comm_code::copy_memory, &req))
		return false;

	if (return_size)
		*return_size = req.cm_return_size;

	return true;
}

PVOID alloc_memory_ex(PVOID address, DWORD size)
{
	operation_data req = {};

	req.am_pid = driver_pid;
	req.am_size = size;
	req.am_in_address = address;

	if (!send_message(comm_code::alloc_memory, &req))
		return 0;

	set_last_error(req.status_code);

	return req.am_out_address;
}

void free_memory_ex(PVOID address)
{
	operation_data req = {};

	req.fm_pid = driver_pid;
	req.fm_address = address;

	if (!send_message(comm_code::free_memory, &req))
		return;

	set_last_error(req.status_code);
}

void fake_enclave_ex(PVOID address)
{
	operation_data req = {};

	req.fe_pid = driver_pid;
	req.fe_address = address;

	if (!send_message(comm_code::fake_enclave, &req))
		return;

	set_last_error(req.status_code);
}