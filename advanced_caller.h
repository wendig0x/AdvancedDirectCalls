#pragma once

#include <stdint.h>
#include <Windows.h>
#include <intrin.h>
#include <stdarg.h>

extern "C" int32_t __fastcall x_syscall(const uint32_t syscall_num, const uint32_t args_num, uintptr_t syscall_addr, const uint64_t * arg_package);


class SysCall {
private:

	NTSTATUS status { 0 };
	uintptr_t dll_base { 0 }, syscall_addr { 0 }, address{ 0 };
	uint16_t ordinal{ 0 };

	unsigned char pBuf[32] { 0 };

	const BYTE prolog_syscall[4] =
	{
		0x4C, 0x8B, 0xD1, 0xB8	// mov r10, rcx mov eax, ...
	};

	[[nodiscard]] inline uintptr_t get_syscall_addr(uintptr_t stub_addr) noexcept;

	[[nodiscard]] int32_t get_syscall_index(LPCSTR name_api) noexcept;
	
public:

    template<typename... Args>
	int32_t __stdcall call(LPCSTR name_api, Args ... args, ...);

	SysCall();
};

SysCall::SysCall()
{
	dll_base = reinterpret_cast<uintptr_t>(GetModuleHandleA("ntdll.dll"));
}

[[nodiscard]] inline uintptr_t SysCall::get_syscall_addr(uintptr_t stub_addr) noexcept
{
	uintptr_t p_syscall = 0;

	// Since Windows 10 TH2  // syscall  // BYTE вместо unsigned char
	if (*(reinterpret_cast<BYTE*>(stub_addr + 0x12)) == 0x0F &&  // 0f 05 syscall   (+18 байт от начала стаба)
		*(reinterpret_cast<BYTE*>(stub_addr + 0x13)) == 0x05)
	{
		p_syscall = stub_addr + 0x12;  // адрес инструкции syscall
	}

	// From Windows XP to Windows 10 TH2
	else if (*(reinterpret_cast<BYTE*>(stub_addr + 0x8)) == 0x0F && // 0f 05 syscall   (+8 байт от начала стаба)
		*(reinterpret_cast<BYTE*>(stub_addr + 0x9)) == 0x05)
	{
		p_syscall = stub_addr + 0x8;
	}

	return p_syscall;
};

[[nodiscard]] int32_t SysCall::get_syscall_index(LPCSTR name_api) noexcept
{
	if (!dll_base) return 0xFFFFFFFF;

	uint32_t call_number{ 0 };

	const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base);
	const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE) return 0xFFFFFFFF;

	const auto pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((LPBYTE)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (pExportDirectory == nullptr) return 0xFFFFFFFF;

	const auto functions_table = reinterpret_cast<DWORD*>((LPBYTE)pDosHeader + pExportDirectory->AddressOfFunctions);
	const auto names_table = reinterpret_cast<DWORD*>((LPBYTE)pDosHeader + pExportDirectory->AddressOfNames);
	const auto ordinals_table = reinterpret_cast<WORD*>((LPBYTE)pDosHeader + pExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; ++i)
	{
		ordinal = ordinals_table[i];
		address = dll_base + functions_table[ordinal];

		memset(&pBuf, 0, 32);

		auto pAddr = reinterpret_cast<VOID*>((LPBYTE)pDosHeader + functions_table[ordinals_table[i]]);
		auto szName = reinterpret_cast<char*>((LPBYTE)pDosHeader + names_table[i]);

		if (pAddr == nullptr || szName == nullptr) break;

		memcpy(&pBuf, pAddr, 32);

		for (int x = 0; x < sizeof(prolog_syscall); ++x)
		{

			if (pBuf[x] != prolog_syscall[x])
			break;

			if ((x == sizeof(prolog_syscall) - 1) && !strcmp(name_api, szName)) {

				syscall_addr = get_syscall_addr(address);

				if (!syscall_addr) 
				return 0xFFFFFFFF;

				call_number = pBuf[4];
				break;
			}
		}
	}
	return call_number;
}

template<typename... Args>
int32_t __stdcall SysCall::call(LPCSTR name_api, Args ... args, ...)
 {
	uint64_t arg_table[20]{ 0 };

	int syscall_idx = get_syscall_index(name_api);

	if (syscall_idx == 0xFFFFFFFF) 
		return 0xFFFFFFFF;

	va_list variadic_arg;
	va_start(variadic_arg, name_api);

	const auto arg_count = static_cast<uint32_t>(sizeof...(args));

	for (auto idx = 0; idx < arg_count; ++idx)
	{
		arg_table[idx] = va_arg(variadic_arg, uint64_t);
	}

	va_end(variadic_arg);

	return x_syscall(syscall_idx, arg_count, syscall_addr, arg_table);
}