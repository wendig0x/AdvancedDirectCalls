
#include <Windows.h>
#include <iostream>
#include "winternl.h"
#include "advanced_caller.h"

using namespace std;

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);


int main() {


	WCHAR chDmpFile[MAX_PATH] = L"\\??\\";
	WCHAR chWinPath[MAX_PATH];

	GetCurrentDirectory(MAX_PATH, chWinPath);

	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), chWinPath);
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), L"\\test_file777.txt");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

	if (RtlInitUnicodeString == nullptr) {
		return 0;
	}

	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, chDmpFile);

	HANDLE hTestFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;

	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SysCall directcall;

	NTSTATUS status = directcall.call("ZwCreateFile",
		&hTestFile,
		FILE_GENERIC_WRITE,
		&FileObjectAttributes,
		&IoStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);