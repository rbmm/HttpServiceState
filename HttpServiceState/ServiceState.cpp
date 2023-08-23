#include "stdafx.h"

_NT_BEGIN

#include "print.h"

#define _DBG_

#include "ServiceState.h"

struct HTTPAPI_EA_VALUE : HTTPAPI_VERSION
{
	ULONG dwFlags;
	HANDLE unused;
	PVOID reserved;//must be 0
};

C_ASSERT(sizeof(HTTPAPI_EA_VALUE)== 0x18);

static const char UlOpenPacket000[] = "UlOpenPacket000";

void InitEa(PFILE_FULL_EA_INFORMATION ea, HTTPAPI_VERSION version, ULONG dwFlags)
{
	ea->EaNameLength = sizeof(UlOpenPacket000) - 1;
	ea->EaValueLength = sizeof(HTTPAPI_EA_VALUE);
	memcpy(ea->EaName, UlOpenPacket000, sizeof(UlOpenPacket000));

	HTTPAPI_EA_VALUE* value = (HTTPAPI_EA_VALUE*)&ea->EaName[sizeof(UlOpenPacket000)];
	*static_cast<HTTPAPI_VERSION*>(value) = version;
	value->dwFlags = dwFlags;
}

NTSTATUS QueryServiceState(_In_ HTTP_MGMT_ROOT_INFO* mri, _Out_ HTTP_SERVICE_STATE** ppState)
{
	UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\Device\\Http\\Communication");
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	union {
		FILE_FULL_EA_INFORMATION ea;
		UCHAR EaBuf[offsetof(FILE_FULL_EA_INFORMATION, EaName) + sizeof(UlOpenPacket000) + sizeof(HTTPAPI_EA_VALUE)]{};
	};

	InitEa(&ea, HTTPAPI_VERSION_2, 0);

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtCreateFile(&hFile, FILE_GENERIC_READ|FILE_GENERIC_WRITE, &oa, &iosb, 
		0, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, &ea, sizeof(EaBuf));

	if (0 <= status)
	{
		ULONG cb = 0x100;

		PVOID buf;

		do 
		{
			status = STATUS_NO_MEMORY;

			if (buf = LocalAlloc(LMEM_FIXED, cb))
			{
				if (0 > (status = NtDeviceIoControlFile(hFile, 0, 0, 0, &iosb, 
					CTL_CODE(FILE_DEVICE_NETWORK, 0x25, METHOD_OUT_DIRECT, FILE_READ_ACCESS),
					mri, sizeof(HTTP_MGMT_ROOT_INFO), buf, cb)))
				{
					LocalFree(buf);
				}
				else
				{
					*ppState = (HTTP_SERVICE_STATE*)buf;
				}
				buf = 0;

				cb = (ULONG)iosb.Information;
			}
		} while (STATUS_BUFFER_OVERFLOW == status);

		if (buf)
		{
			LocalFree(buf);
		}

		NtClose(hFile);
	}

	return status;
}

NTSTATUS OpenExistingQueue(_Out_ PHANDLE FileHandle, 
						   _In_ ACCESS_MASK DesiredAccess, 
						   _In_ HTTPAPI_VERSION version, 
						   _In_ PCWSTR Name, 
						   _In_ ULONG NameLength)
{
	UNICODE_STRING ObjectName{};
	int len  = 0;

	while (0 < (len = _snwprintf(ObjectName.Buffer, len, L"\\Device\\Http\\ReqQueue\\%.*s", NameLength, Name)))
	{
		if (ObjectName.Buffer)
		{
			ObjectName.Length = (USHORT)(len * sizeof(WCHAR));
			ObjectName.MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));

			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

			union {
				FILE_FULL_EA_INFORMATION ea;
				UCHAR EaBuf[offsetof(FILE_FULL_EA_INFORMATION, EaName) + sizeof(UlOpenPacket000) + sizeof(HTTPAPI_EA_VALUE)]{};
			};

			InitEa(&ea, version, HTTP_CREATE_REQUEST_QUEUE_FLAG_OPEN_EXISTING);

			IO_STATUS_BLOCK iosb;
			return NtCreateFile(FileHandle, DesiredAccess, &oa, &iosb, 
				0, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, 0, &ea, sizeof(EaBuf));
		}

		ObjectName.Buffer = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

NTSTATUS QueryServiceState(_Out_ HTTP_SERVICE_STATE** ppState)
{
	HTTP_MGMT_ROOT_INFO mri = {HTTP_MGMT_ROOT_INFO::UlpReadAndCopyServiceState};

	return QueryServiceState(&mri, ppState);
}

//////////////////////////////////////////////////////////////////////////
//

PCWSTR GetStateName(HTTP_ENABLED_STATE state, PWSTR buf, ULONG cch)
{
	switch (state)
	{
	case HttpEnabledStateActive: return L"Active";
	case HttpEnabledStateInactive: return L"Inactive";
	}

	swprintf_s(buf, cch, L"s[%x]", state);
	return buf;
}

PCWSTR GetLogFormatName(HTTP_LOGGING_TYPE Format, PWSTR buf, ULONG cch)
{
	switch (Format)
	{
	case HttpLoggingTypeW3C: return L"W3C";
	case HttpLoggingTypeIIS: return L"IIS";
	case HttpLoggingTypeNCSA: return L"NCSA";
	case HttpLoggingTypeRaw: return L"Raw";
	}

	swprintf_s(buf, cch, L"[%x]", Format);
	return buf;
}

void PrintUrlGroup(HTTP_URL_GROUP* Group)
{
	WCHAR buf[32];
	DbgPrint("\tGroup: %016I64x\r\n\tQueue: %016I64x\r\n\t%s\r\n", Group->UrlGroupId, Group->QueueId, 
		GetStateName(Group->state.State, buf, _countof(buf)));
	
	if (ULONG QueueNameLen = Group->QueueNameLen)
	{
		DbgPrint("\t\tQueue: \"%.*s\"\r\n", QueueNameLen/sizeof(WCHAR), Group->QueueName);
	}

	if (ULONG UrlCount = Group->UrlCount)
	{
		DbgPrint("\tRegisteredUrls:\r\n");
		PCWSTR RegisteredUrls = Group->RegisteredUrls;
		do 
		{
			DbgPrint("\t\t%s\r\n", RegisteredUrls);
			RegisteredUrls += wcslen(RegisteredUrls) + 1;
		} while (--UrlCount);
	}

	if (ULONG DirectoryNameLength = Group->DirectoryNameLength)
	{
		DbgPrint("\t\tLog: \"%.*s\"\r\n", DirectoryNameLength/sizeof(WCHAR), Group->DirectoryName);
	}
}

void PrintServerSession(_In_ HTTP_SERVER_SESSION* Session)
{
	WCHAR buf[32];
	DbgPrint("Session: %016I64x\r\n%s\r\nVersion %x.%x\r\n", Session->ServerSessionId, 
		GetStateName(Session->state.State, buf, _countof(buf)),
		Session->version.HttpApiMajorVersion, Session->version.HttpApiMinorVersion);

	if (ULONG DirectoryNameLength = Session->DirectoryNameLength)
	{
		DbgPrint("LogFormat: %s\r\nLog: \"%.*s\"\r\n", GetLogFormatName(Session->Format, buf, _countof(buf)),
			DirectoryNameLength/sizeof(WCHAR), Session->DirectoryName);
	}
}

typedef struct SYSTEM_PROCESS_ID_INFORMATION
{
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} *PSYSTEM_PROCESS_ID_INFORMATION;

ULONG PrintTagInfo(_In_ HANDLE ProcessId, _In_ HANDLE Tag);

void PrintProcessDetails(_In_ HANDLE ProcessId, _In_ HANDLE Tag)
{
	SYSTEM_PROCESS_ID_INFORMATION spii = { ProcessId, { 0, 0x200 } };
	NTSTATUS status;

	do 
	{
		status = STATUS_NO_MEMORY;
		if (spii.ImageName.Buffer = (PWSTR)LocalAlloc(LMEM_FIXED, spii.ImageName.MaximumLength))
		{
			if (0 <= (status = NtQuerySystemInformation(
				SystemProcessIdInformation, &spii, sizeof(spii), 0)))
			{
				DbgPrint("%p < %wZ >\r\n", ProcessId, &spii.ImageName);
			}

			LocalFree(spii.ImageName.Buffer);
		}

	} while (STATUS_INFO_LENGTH_MISMATCH == status);

	if (0 > status)
	{
		DbgPrint("PID=%p -> %x\r\n", ProcessId, status); 
	}

	CLIENT_ID cid = { ProcessId };
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	HANDLE hProcess;
	if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid)))
	{
		ULONG cb = 0x200;
		do 
		{
			status = STATUS_NO_MEMORY;

			if (POBJECT_NAME_INFORMATION poni = (POBJECT_NAME_INFORMATION)LocalAlloc(LMEM_FIXED, cb))
			{
				if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, poni, cb, &cb)))
				{
					DbgPrint("win32= < %wZ >\r\n", &poni->Name);
				}

				LocalFree(poni);
			}
		} while (STATUS_INFO_LENGTH_MISMATCH == status);

		NtClose(hProcess);
	}

	if (Tag)
	{
		PrintTagInfo(ProcessId, Tag);
	}
}
extern volatile const UCHAR guz = 0;

#undef _NTDDK_
#include <sddl.h>

void ShowSD(HANDLE hObject)
{
	PVOID stack = alloca(guz);

	union {
		PVOID buf = 0;
		PSECURITY_DESCRIPTOR SecurityDescriptor;
	};

	ULONG cb = 0, rcb = 0x40;

	NTSTATUS status;

	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		status = NtQuerySecurityObject(hObject, 
			DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION, 
			SecurityDescriptor, cb, &rcb);

	} while (STATUS_BUFFER_TOO_SMALL == status);
	
	if (0 <= status)
	{
		PWSTR pwsz;
		if (ConvertSecurityDescriptorToStringSecurityDescriptorW(SecurityDescriptor, SDDL_REVISION,
			DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION, &pwsz, 0))
		{
			DbgPrint("\tSD= %s\n", pwsz);
			LocalFree(pwsz);
		}
	}
}

void PrintServerRequestQueue(_In_ HTTP_REQUEST_QUEUE* Queue)
{
	WCHAR buf[32];
	DbgPrint("Queue: %016I64x\r\n%s\r\nVersion %x.%x\r\n", Queue->QueueId, 
		GetStateName(Queue->state, buf, _countof(buf)),
		Queue->version.HttpApiMajorVersion, Queue->version.HttpApiMinorVersion);

	if (ULONG NameLen = Queue->NameLength/sizeof(WCHAR))
	{
		DbgPrint("Name: \"%.*s\"\r\n", NameLen, Queue->Name);

		HANDLE RequestQueueHandle;
		if (NOERROR == OpenExistingQueue(&RequestQueueHandle, READ_CONTROL, Queue->version, Queue->Name, NameLen))
		{
			ShowSD(RequestQueueHandle);
			NtClose(RequestQueueHandle);
		}
	}

	if (HANDLE ControllerProcessId = Queue->ControllerProcessId)
	{
		DbgPrint("Controller:\r\n");
		PrintProcessDetails(ControllerProcessId, Queue->ControllerProcessTag);
	}

	if (ULONG ActiveProcessCount = Queue->ActiveProcessCount)
	{
		DbgPrint("ActiveProcessCount: %x\r\n", ActiveProcessCount);
		HANDLE* rgProcessesId = Queue->rgProcessesId;
		HANDLE* rgProcessTag = Queue->rgProcessTag;
		do 
		{
			PrintProcessDetails(*rgProcessesId++, *rgProcessTag++);
		} while (--ActiveProcessCount);
	}
}

NTSTATUS QueryServiceState_I()
{
	HTTP_SERVICE_STATE* pState;
	NTSTATUS status = QueryServiceState(&pState);

	if (0 <= status)
	{
		if (HTTP_REQUEST_QUEUE* Queue = pState->firstQueue)
		{
			do 
			{
				PrintServerRequestQueue(Queue);
			} while (Queue = Queue->next);
		}
		
		if (HTTP_SERVER_SESSION* Session = pState->firstSession)
		{
			do 
			{
				PrintServerSession(Session);
				if (HTTP_URL_GROUP* Group = Session->firstGroup)
				{
					do 
					{
						PrintUrlGroup(Group);

					} while (Group = Group->next);
				}
			} while (Session = Session->next);
		}

		LocalFree(pState);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////
//

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

BEGIN_PRIVILEGES(tp_DBR, 3)
	LAA(SE_DEBUG_PRIVILEGE),
	LAA(SE_BACKUP_PRIVILEGE),
	LAA(SE_RESTORE_PRIVILEGE),
END_PRIVILEGES

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityDelegation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

NTSTATUS AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken, hNewToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &hToken)))
	{
		status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
			const_cast<OBJECT_ATTRIBUTES*>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

		NtClose(hToken);

		if (0 <= status)
		{
			if (STATUS_SUCCESS == (status = NtAdjustPrivilegesToken(hNewToken, 
				FALSE, const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0)))
			{
				status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
			}

			NtClose(hNewToken);
		}
	}

	return status;
}

NTSTATUS QueryServiceState()
{
	AdjustPrivileges(&tp_DBR);
	NTSTATUS hr = QueryServiceState_I();
	RtlRevertToSelf();

	if (hr)
	{
		DbgPrint("status = %x\r\n", hr);
		hr |= FACILITY_NT_BIT;
	}

	return hr;
}

void InitTag();

void CALLBACK ep(void*)
{
	InitPrintf();

	ExitProcess(PrintError(QueryServiceState()));
}

_NT_END