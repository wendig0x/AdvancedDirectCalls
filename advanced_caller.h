#pragma once

#include <stdint.h>
#include <Windows.h>
#include <intrin.h>
#include <stdarg.h>

extern "C" size_t __fastcall x_syscall(const size_t syscall_idx, const size_t args_count, uintptr_t syscall_addr, const uint64_t * arg_table);


class SysCall {
private:

	NTSTATUS status { 0 };
	uintptr_t dll_base { 0 }, syscall_addr { 0 }, address{ 0 };
	uint16_t ordinal{ 0 };

	unsigned char pBuf[32] { 0 };

	const BYTE prolog_syscall[4] { 0x4C, 0x8B, 0xD1, 0xB8 };		// mov r10, rcx, mov eax, ...
	
	[[nodiscard]] inline uintptr_t get_syscall_addr(uintptr_t stub_addr) noexcept;

	[[nodiscard]] size_t get_syscall_index(LPCSTR name_api) noexcept;
	
public:

	template<typename T>
	size_t __stdcall call(LPCSTR name_api, const T& arg)
	{
		constexpr size_t arguments_count = 1;
		std::uint64_t arguments_table[1] = {};
		fill_arguments(arguments_table, arguments_count, arg);

		size_t syscall_idx = get_syscall_index(name_api);
		return x_syscall(syscall_idx, arguments_count, syscall_addr, arguments_table);
	}

    template<typename T, typename... Args>
	size_t __stdcall call(LPCSTR name_api, const T& arg, const Args&... args) 
	{
		constexpr size_t arguments_count = sizeof...(args) + 1;
		std::uint64_t arguments_table[arguments_count] = {};
		fill_arguments(arguments_table, arguments_count, arg, args...);

		size_t syscall_idx = get_syscall_index(name_api);
		return x_syscall(syscall_idx, arguments_count, syscall_addr, arguments_table);
	}

	SysCall();

private:
	template<typename T, typename... Args>
	void fill_arguments(std::uint64_t* table, const std::size_t size, const T& arg, const Args&... args) {
		fill_arguments(table, size, arg);
		fill_arguments(table, size - 1, args...);
	}
	
	template<typename T>
	void fill_arguments(std::uint64_t* table, const std::size_t size, const T& arg) {
		table[size - 1] = reinterpret_cast<std::uint64_t>(&arg);
	}

};

SysCall::SysCall()
{
	dll_base = reinterpret_cast<uintptr_t>(GetModuleHandleA("ntdll.dll"));
}

[[nodiscard]] inline uintptr_t SysCall::get_syscall_addr(uintptr_t stub_addr) noexcept
{
	uintptr_t p_syscall = 0;

	// Since Windows 10 TH2
	if (*(reinterpret_cast<BYTE*>(stub_addr + 0x12)) == 0x0F &&
		*(reinterpret_cast<BYTE*>(stub_addr + 0x13)) == 0x05)
	{
		p_syscall = stub_addr + 0x12;
	}

	// From Windows XP to Windows 10 TH2
	else if (*(reinterpret_cast<BYTE*>(stub_addr + 0x8)) == 0x0F &&
		*(reinterpret_cast<BYTE*>(stub_addr + 0x9)) == 0x05)
	{
		p_syscall = stub_addr + 0x8;
	}

	return p_syscall;
};

[[nodiscard]] size_t SysCall::get_syscall_index(LPCSTR name_api) noexcept
{
	if (!dll_base) return static_cast<size_t>(-1);

	size_t call_number { 0 };

	const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base);
	const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE) return static_cast<size_t>(-1);

	const auto pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((LPBYTE)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	const auto functions_table = reinterpret_cast<unsigned char*>((LPBYTE)pDosHeader + pExportDirectory->AddressOfFunctions);
	const auto names_table = reinterpret_cast<unsigned char*>((LPBYTE)pDosHeader + pExportDirectory->AddressOfNames);
	const auto ordinals_table = reinterpret_cast<WORD*>((LPBYTE)pDosHeader + pExportDirectory->AddressOfNameOrdinals);

	for (size_t i = 0; i < pExportDirectory->NumberOfFunctions; ++i)
	{
		ordinal = ordinals_table[i];
		address = dll_base + functions_table[ordinal];

		memset(&pBuf, 0, 32);

		auto pAddr = reinterpret_cast<VOID*>((LPBYTE)pDosHeader + functions_table[ordinals_table[i]]);
		auto szName = reinterpret_cast<char*>((LPBYTE)pDosHeader + names_table[i]);

		memcpy(&pBuf, pAddr, 32);

		for (int x = 0; x < sizeof(prolog_syscall); ++x)
		{
			if (pBuf[x] != prolog_syscall[x])
			break;

			if ((x == sizeof(prolog_syscall) - 1) && !strcmp(name_api, szName)) {

				syscall_addr = get_syscall_addr(address);

				if (!syscall_addr) 
				return static_cast<size_t>(-1);

				call_number = pBuf[4];
				break;
			}
		}
	}
	return call_number;
}
