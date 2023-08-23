#pragma once

void PrintWA_v(PCWSTR format, ...);

#define DbgPrint(fmt, ...) PrintWA_v(_CRT_WIDE(fmt), __VA_ARGS__ )

void PrintUTF8(PCWSTR pwz, ULONG cch);

inline void PrintUTF8(PCWSTR pwz)
{
	PrintUTF8(pwz, (ULONG)wcslen(pwz));
}

HRESULT PrintError(HRESULT dwError);

void InitPrintf();
