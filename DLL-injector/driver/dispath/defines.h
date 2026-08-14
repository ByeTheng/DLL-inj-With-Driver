#pragma once
#include "../../xor/xor.h"

///////////////////////////////////////////////////////////
enum comm_code
{
	is_driver_load,
	process_base_address,
	alloc_kernel_memory,
	copy_memory,
	alloc_memory,
	free_memory,
	fake_enclave
};

typedef struct operation_data
{
	/*status code*/
	int64_t status_code;
	/*status code*/

	/*is driver load*/
	ULONG load_code;
	/*is driver load*/

	/*process base address*/
	ULONG pba_pid;
	PVOID pba_out_address;
	/*process base address*/

	/*alloc kernel memory*/
	ULONG akm_pid;
	ULONG akm_size;
	PVOID akm_address;
	/*alloc kernel memory*/

	/*copy memory*/
	PVOID cm_buffer;
	PVOID cm_address;
	ULONG cm_size;
	ULONG cm_pid;
	ULONG cm_return_size;
	bool cm_write;
	/*copy memory*/

	/*alloc memory*/
	ULONG am_pid;
	PVOID am_in_address;
	PVOID am_out_address;
	ULONG am_size;
	/*alloc memory*/

	/*free memory*/
	ULONG fm_pid;
	PVOID fm_address;
	/*free memory*/

	/*fake enclave*/
	ULONG fe_pid;
	PVOID fe_address;
	/*fake enclave*/
};
///////////////////////////////////////////////////////////