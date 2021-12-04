#include <Windows.h>

int main() {

	
	NTSTATUS status;
	SysCall directcall;
	
	status = directcall.call("NtRaiseHardError", 
		0x50000018L, 
		0x00000003L, 
		3, 
		(PULONG_PTR)parameters, 
		NULL, 
		&Error);

//	if(NT_SUCCESS(status)) ...

    return 0;
}