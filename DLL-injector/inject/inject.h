#pragma once

/////////////////////////////////
HWND exterior_window_handle = 0;

typedef struct _load_library_c
{
	int32_t status;
	uint64_t fn_load_library_a;
	uint64_t module_base;
	char module_name[80];
} load_library_c, *pload_library_c;

typedef struct _main_c
{
	int32_t status;
	uintptr_t fn_dll_main;
	HINSTANCE dll_base;
} main_c, *pmain_c;

typedef struct _client_id_c
{
	HANDLE unique_process;
	HANDLE unique_thread;
} client_id_c;

typedef struct _thread_basic_information
{
	NTSTATUS exit_status;
	PVOID teb_base_address;
	client_id_c client_id;
	KAFFINITY affinity_mask;
	LONG priority;
	LONG base_priority;
} thread_basic_information, *pthread_basic_information;

typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
/////////////////////////////////

/////////////////////////////////
uint8_t remote_load_library[96] =
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
	0x83, 0x38, 0x00, 0x75, 0x3D, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
	0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x18, 0x48, 0x8B, 0xC8, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B,
	0x4C, 0x24, 0x20, 0x48, 0x89, 0x41, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};

uint8_t remote_call_dll_main[92] =
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
}; 

DWORD shell_data_offset = 0x6;
/////////////////////////////////

/////////////////////////////////
uintptr_t call_remote_load_library(DWORD thread_id, LPCSTR dll_name)
{
	HMODULE nt_dll = LoadLibraryW(xor_w(L"ntdll.dll"));

	PVOID alloc_shell_code = alloc_memory_ex(0, 0x1000);

	DWORD shell_size = sizeof(remote_load_library) + sizeof(load_library_c);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	RtlCopyMemory(alloc_local, &remote_load_library, sizeof(remote_load_library));

	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_load_library);

	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;

	load_library_c* ll_data = (load_library_c*)((uintptr_t)alloc_local + sizeof(remote_load_library));

	ll_data->fn_load_library_a = (uintptr_t)LoadLibraryA;
	strcpy_s(ll_data->module_name, 80, dll_name);

	write_memory_ex(alloc_shell_code, alloc_local, shell_size);

	HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);

	while (ll_data->status != 2)
	{
		PostThreadMessage(thread_id, WM_NULL, 0, 0);
		read_memory_ex((PVOID)shell_data, (PVOID)ll_data, sizeof(load_library_c));
		Sleep(10);
	} 
	
	uintptr_t mod_base = ll_data->module_base;

	UnhookWindowsHookEx(h_hook);

	free_memory_ex(alloc_shell_code);

	VirtualFree(alloc_local, 0, MEM_RELEASE);

	return mod_base;
}

BOOL call_via_set_windows_hook_ex(DWORD thread_id, PVOID dll_base, PIMAGE_NT_HEADERS nt_header)
{
	HMODULE nt_dll = LoadLibraryW(xor_w(L"ntdll.dll"));

	PVOID alloc_shell_code = alloc_memory_ex(0, 0x1000);

	DWORD shell_size = sizeof(remote_call_dll_main) + sizeof(main_c);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	RtlCopyMemory(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));

	ULONGLONG shell_data = (ULONGLONG)alloc_shell_code + sizeof(remote_call_dll_main);

	*(ULONGLONG*)((ULONGLONG)alloc_local + shell_data_offset) = shell_data;

	pmain_c main_data = (pmain_c)((ULONGLONG)alloc_local + sizeof(remote_call_dll_main));

	main_data->dll_base = (HINSTANCE)dll_base;
	main_data->fn_dll_main = ((ULONGLONG)dll_base + nt_header->OptionalHeader.AddressOfEntryPoint);

	write_memory_ex(alloc_shell_code, alloc_local, shell_size);

	HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);

	while (main_data->status != 2)
	{
		PostThreadMessage(thread_id, WM_NULL, 0, 0);
		read_memory_ex((PVOID)shell_data, (PVOID)main_data, sizeof(main_c));
		Sleep(10);
	}

	UnhookWindowsHookEx(h_hook);

	free_memory_ex(alloc_shell_code);

	VirtualFree(alloc_local, 0, MEM_RELEASE);

	return TRUE;
}

PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
{
	PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);

	for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
	{
		if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
		{
			return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);
		}
	}

	return 0;
}

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc)
{
	HMODULE h_module = LoadLibraryExA(modname, NULL, DONT_RESOLVE_DLL_REFERENCES);

	uintptr_t func_offset = (uintptr_t)GetProcAddress(h_module, modfunc);

	func_offset -= (uintptr_t)h_module;

	FreeLibrary(h_module);

	return func_offset;
}

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS NtHead)
{
	typedef struct _RELOC_ENTRY
	{
		ULONG to_rva;
		ULONG size;

		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];

	} RELOC_ENTRY, *PRELOC_ENTRY;

	ULONGLONG delta_offset = (ULONGLONG)p_remote_img - NtHead->OptionalHeader.ImageBase;
	if (!delta_offset)
		return TRUE;

	else if (!(NtHead->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
		return FALSE;

	PRELOC_ENTRY reloc_ent = (PRELOC_ENTRY)rva_va(NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, NtHead, p_local_img);
	ULONGLONG reloc_end = (ULONGLONG)reloc_ent + NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return TRUE;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;

		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, NtHead, p_local_img);

				if (!fix_va)
					fix_va = (uintptr_t)p_local_img;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (PRELOC_ENTRY)((LPBYTE)reloc_ent + reloc_ent->size);
	}
	return TRUE;
}

BOOL resolve_import(DWORD thread_id, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_head, p_local_img);

	if (!nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) 
		return true;

	LPSTR module_name = 0;

	while ((module_name = (LPSTR)rva_va(import_desc->Name, nt_head, p_local_img)))
	{
		uintptr_t base_image = call_remote_load_library(thread_id, module_name);

		if (!base_image)
			return false;

		PIMAGE_THUNK_DATA ih_data = (PIMAGE_THUNK_DATA)rva_va(import_desc->FirstThunk, nt_head, p_local_img);

		while (ih_data->u1.AddressOfData)
		{
			if (ih_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)(ih_data->u1.Ordinal & 0xFFFF));
			else
			{
				IMAGE_IMPORT_BY_NAME* ibn = (PIMAGE_IMPORT_BY_NAME)rva_va(ih_data->u1.AddressOfData, nt_head, p_local_img);
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)ibn->Name);
			} ih_data++;
		} import_desc++;
	} return true;
}

void write_sections(PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);

	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		write_memory_ex((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), (PVOID)((uintptr_t)local_image + section->PointerToRawData), section->SizeOfRawData);
	}
}

void erase_discardable_sect(PVOID p_module_base, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);

	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			PVOID zero_memory = VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			write_memory_ex((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), zero_memory, section->SizeOfRawData);
			VirtualFree(zero_memory, 0, MEM_RELEASE);
		}
	}
}

DWORD get_process_id_and_thread_id_by_window_class(HWND window, PDWORD p_thread_id)
{
	DWORD process_id = 0;
	*p_thread_id = GetWindowThreadProcessId(window, &process_id);

	return process_id;
}

PVOID get_dll_by_file(LPCWSTR file_path)
{
	HANDLE h_dll = CreateFileW(file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_dll == INVALID_HANDLE_VALUE)
		return NULL;

	DWORD dll_file_sz = GetFileSize(h_dll, NULL);
	PVOID dll_buffer = VirtualAlloc(NULL, dll_file_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(h_dll, dll_buffer, dll_file_sz, NULL, FALSE) || *(PDWORD)dll_buffer != 9460301)
	{
		VirtualFree(dll_buffer, 0, MEM_RELEASE);
		goto exit;
	}

exit:
	CloseHandle(h_dll);
	return dll_buffer;
}

BOOL CALLBACK enum_windows(HWND hwnd, LPARAM l_param)
{
	DWORD proc_id;
	GetWindowThreadProcessId(hwnd, &proc_id);

	if (proc_id == l_param)
	{
		exterior_window_handle = hwnd;
		return FALSE;
	}
	return TRUE;
}

enum inject_codes : int32_t
{
	process_error,
	invalid_dll,
	invalid_pe_header,
	alloc_error,
	reloc_error,
	resolve_imports_error,
	inject_succes
};

inject_codes face_injector_v4(DWORD process_id, LPCWSTR dll_path, bool show_log = true)
{
	DWORD thread_id;

	EnumWindows(enum_windows, process_id);
	get_process_id_and_thread_id_by_window_class(exterior_window_handle, &thread_id);

	if (!process_id || !thread_id)
		return inject_codes::process_error;

	PVOID dll_image = get_dll_by_file(dll_path);

	if (!dll_image)
		return inject_codes::invalid_dll;

	PIMAGE_NT_HEADERS dll_nt_head = RtlImageNtHeader(dll_image);

	if (!dll_nt_head)
		return inject_codes::invalid_pe_header;

	PVOID allocate_base = alloc_memory_ex(0, dll_nt_head->OptionalHeader.SizeOfImage);

	if (!allocate_base)
		return inject_codes::alloc_error;

	if (show_log)
		printf(xor_a("allocate base 0x%llX\n"), allocate_base);

	if (!relocate_image(allocate_base, dll_image, dll_nt_head))
		return inject_codes::reloc_error;

	if (show_log)
		printf(xor_a("relocate sucess\n"));

	if (!resolve_import(thread_id, dll_image, dll_nt_head))
		return inject_codes::resolve_imports_error;

	if (show_log)
		printf(xor_a("resolve imports sucess\n"));

	write_sections(allocate_base, dll_image, dll_nt_head);

	if (show_log)
		printf(xor_a("write section sucess\n"));

	call_via_set_windows_hook_ex(thread_id, allocate_base, dll_nt_head);

	if (show_log)
		printf(xor_a("call dll main success\n"));

	erase_discardable_sect(allocate_base, dll_nt_head);
	VirtualFree(dll_image, 0, MEM_RELEASE);

	fake_enclave_ex(allocate_base);

	return inject_codes::inject_succes;
}