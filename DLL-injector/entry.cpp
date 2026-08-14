#include "stdafx/stdafx.h"

void msg_and_exit(const char* msg)
{
	printf(msg);
	Sleep(2500);
	ExitProcess(EXIT_SUCCESS);
}

int main()
{
	if (!driver_setup())
		msg_and_exit(xor_a("error driver setup"));

	if (!is_driver_load_ex())
	{
		mmap_driver();

		Sleep(2500);

		system("cls");

		if (!is_driver_load_ex())
			msg_and_exit(xor_a("error driver load"));
	}

	DWORD process_id = get_process_id_by_name(xor_w(L"cod.exe"));

	if (!process_id)
		msg_and_exit(xor_a("get process id error"));

	attach_driver(process_id);

	inject_codes inject_status = face_injector_v4(process_id, xor_w(L"dummy.dll"));

	printf("\n");

	switch (inject_status)
	{
	case inject_codes::process_error:
	{
		msg_and_exit(xor_a("process not found"));
	} break;

	case inject_codes::invalid_dll:
	{
		msg_and_exit(xor_a("invalid dll image"));
	} break;

	case inject_codes::invalid_pe_header:
	{
		msg_and_exit(xor_a("invalid pe header"));
	} break;

	case inject_codes::alloc_error:
	{
		msg_and_exit(xor_a("allocate error"));
	} break;

	case inject_codes::reloc_error:
	{
		msg_and_exit(xor_a("relocate error"));
	} break;

	case inject_codes::resolve_imports_error:
	{
		msg_and_exit(xor_a("resolve imports error"));
	} break;

	case inject_codes::inject_succes:
	{
		msg_and_exit(xor_a("inject sucess!"));
	} break;

	default:
		break;
	}

	Sleep(2500);
	ExitProcess(EXIT_SUCCESS);
}