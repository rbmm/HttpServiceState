#include "stdafx.h"

_NT_BEGIN

typedef enum _TAG_INFO_LEVEL
{
	eTagInfoLevelNameFromTag = 1, // TAG_INFO_NAME_FROM_TAG
	eTagInfoLevelNamesReferencingModule, // TAG_INFO_NAMES_REFERENCING_MODULE
	eTagInfoLevelNameTagMapping, // TAG_INFO_NAME_TAG_MAPPING
	eTagInfoLevelMax
} TAG_INFO_LEVEL;

typedef enum _TAG_TYPE
{
	eTagTypeService = 1,
	eTagTypeMax
} TAG_TYPE;

typedef struct _TAG_INFO_NAME_FROM_TAG_IN_PARAMS
{
	ULONG dwPid;
	ULONG dwTag;
} TAG_INFO_NAME_FROM_TAG_IN_PARAMS, *PTAG_INFO_NAME_FROM_TAG_IN_PARAMS;

typedef struct _TAG_INFO_NAME_FROM_TAG_OUT_PARAMS
{
	ULONG eTagType;
	PWSTR pszName;
} TAG_INFO_NAME_FROM_TAG_OUT_PARAMS, *PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS;

typedef struct _TAG_INFO_NAME_FROM_TAG
{
	TAG_INFO_NAME_FROM_TAG_IN_PARAMS InParams;
	TAG_INFO_NAME_FROM_TAG_OUT_PARAMS OutParams;
} TAG_INFO_NAME_FROM_TAG, *PTAG_INFO_NAME_FROM_TAG;

typedef struct _TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS
{
	ULONG dwPid;
	PWSTR pszModule;
} TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS, *PTAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS;

typedef struct _TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS
{
	ULONG eTagType;
	PWSTR pmszNames;
} TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS, *PTAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS;

typedef struct _TAG_INFO_NAMES_REFERENCING_MODULE
{
	TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS InParams;
	TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS OutParams;
} TAG_INFO_NAMES_REFERENCING_MODULE, *PTAG_INFO_NAMES_REFERENCING_MODULE;

typedef struct _TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS
{
	ULONG dwPid;
} TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS, *PTAG_INFO_NAME_TAG_MAPPING_IN_PARAMS;

typedef struct _TAG_INFO_NAME_TAG_MAPPING_ELEMENT
{
	ULONG eTagType;
	ULONG dwTag;
	PWSTR pszName;
	PWSTR pszGroupName;
} TAG_INFO_NAME_TAG_MAPPING_ELEMENT, *PTAG_INFO_NAME_TAG_MAPPING_ELEMENT;

typedef struct _TAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS
{
	ULONG cElements;
	PTAG_INFO_NAME_TAG_MAPPING_ELEMENT pNameTagMappingElements;
} TAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS, *PTAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS;

typedef struct _TAG_INFO_NAME_TAG_MAPPING
{
	TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS InParams;
	PTAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS pOutParams;
} TAG_INFO_NAME_TAG_MAPPING, *PTAG_INFO_NAME_TAG_MAPPING;


//////////////////////////////////////////////////////////////////////////
//

ULONG
WINAPI
I_QueryTagInformationNotImpl(
							 _In_opt_ PCWSTR /*MachineName*/,
							 _In_ TAG_INFO_LEVEL /*InfoLevel*/,
							 _Inout_ PVOID /*TagInfo*/
							 )
{
	return ERROR_INVALID_FUNCTION;
}

ULONG
WINAPI
I_QueryTagInformationSelect(
							_In_opt_ PCWSTR MachineName,
							_In_ TAG_INFO_LEVEL InfoLevel,
							_Inout_ PVOID TagInfo
					  );

EXTERN_C_START

WINBASEAPI
ULONG
WINAPI
I_QueryTagInformation(
					  _In_opt_ PCWSTR MachineName,
					  _In_ TAG_INFO_LEVEL InfoLevel,
					  _Inout_ PVOID TagInfo
					  );

#ifdef _X86_
#pragma warning(disable: 4483)
#define __imp_I_QueryTagInformation __identifier("_imp__I_QueryTagInformation@12")
#endif

PVOID __imp_I_QueryTagInformation = I_QueryTagInformationSelect;

EXTERN_C_END

ULONG
WINAPI
I_QueryTagInformationSelect(
							_In_opt_ PCWSTR MachineName,
							_In_ TAG_INFO_LEVEL InfoLevel,
							_Inout_ PVOID TagInfo
					  )
{
	PVOID pfn = I_QueryTagInformationNotImpl;

	if (HMODULE hmod = LoadLibraryW(L"sechost.dll"))
	{
		if (PVOID pv = GetProcAddress(hmod, "I_QueryTagInformation"))
		{
			pfn = pv;
		}
	}

	__imp_I_QueryTagInformation = pfn;

	return I_QueryTagInformation(MachineName, InfoLevel, TagInfo);
}

#include "print.h"

ULONG PrintTagInfo(_In_ HANDLE ProcessId, _In_ HANDLE Tag)
{
	TAG_INFO_NAME_FROM_TAG info = { { (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)Tag } };

	// inside [mschine:]services.exe - ScGetServiceNameFromTag called
	// ULONG ScGetServiceNameFromTag(TAG_INFO_NAME_FROM_TAG_IN_PARAMS *, TAG_INFO_NAME_FROM_TAG_OUT_PARAMS * *);
	// all servicess enumerated
	// if (CWin32ServiceRecord::GetServiceRank() == dwTag && 
	//     CWin32ServiceRecord::GetImageRecord()._M_dwPid == dwPid) { found !!
	// 
	ULONG dwError = I_QueryTagInformation(0, eTagInfoLevelNameFromTag, &info);

	if (NOERROR == dwError)
	{
		DbgPrint("\tTag=%x TagType=%x \"%s\"\r\n", info.OutParams.eTagType, info.OutParams.pszName);
		LocalFree(info.OutParams.pszName);
	}
	else
	{
		DbgPrint("I_QueryTagInformation(%p, %p) = %x\r\n", ProcessId, Tag, dwError);
		PrintError(dwError);
	}

	return dwError;
}

_NT_END