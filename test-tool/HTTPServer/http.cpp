#include "stdafx.h"

_NT_BEGIN
#include "../asio/io.h"
#include "print.h"

struct HttpRequest : IO_OBJECT 
{
	enum { e_send = 'dnes', e_recv = 'vcer' };

	ULONG _M_dwThreadId = GetCurrentThreadId();

	~HttpRequest()
	{
		DbgPrint("%s<%p>\n", __FUNCTIONW__, this);
	}

	virtual void CloseObjectHandle(HANDLE hFile)
	{
		if (hFile) HttpCloseRequestQueue(hFile);
	}

	void OnRecv(ULONG dwErrorCode, PHTTP_REQUEST_V2 phr)
	{
		if (dwErrorCode)
		{
			return ;
		}

		DbgPrint("HTTP_REQUEST_FLAG_=%x\n"
			"ConnectionId=%016I64x\n"
			"RequestId=%016I64x\n"
			"UrlContext=%S\n"
			"Version %x.%x\n"
			"verb=%x\n"
			"url=%S\n"
			"BytesReceived=%x\n"
			"RawConnectionId=%016I64x\n", 
			phr->Flags, phr->ConnectionId, phr->RequestId, phr->UrlContext,
			phr->Version.MajorVersion, phr->Version.MinorVersion, phr->Verb,
			phr->pRawUrl, phr->BytesReceived,
			phr->RawConnectionId);

		CHAR buf[0x200];
		ULONG cch = _countof(buf)-1;
		int len = 0;

		union {
			PSOCKADDR pRemoteAddress;
			PSOCKADDR_IN pa4;
			PSOCKADDR_IN6 pa6;
		};

		pRemoteAddress = phr->Address.pRemoteAddress;

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		switch (phr->Address.pLocalAddress->sa_family)
		{
		case AF_INET:
			status = RtlIpv4AddressToStringExA(&pa4->sin_addr, pa4->sin_port, buf, &cch);
			break;
		case AF_INET6:
			status = RtlIpv6AddressToStringExA(&pa6->sin6_addr, pa6->sin6_scope_id, pa6->sin6_port, buf, &cch);
			break;
		}

		if (0 <= status)
		{
			buf[cch - 1] = '\n';
			len = sprintf_s(buf + cch, _countof(buf) - cch, "pid=%x\nctx=%s\nurl=%s\n", 
				GetCurrentProcessId(), (PSTR)phr->UrlContext, phr->pRawUrl);
		}

		if (USHORT EntityChunkCount = phr->EntityChunkCount)
		{
			PHTTP_DATA_CHUNK pEntityChunks = phr->pEntityChunks;
			do 
			{
				DbgPrint("DataChunkType=%x\n", pEntityChunks->DataChunkType);
				switch (pEntityChunks->DataChunkType)
				{
				case HttpDataChunkFromMemory:
					DbgPrint("%.*S\n", pEntityChunks->FromMemory.BufferLength, pEntityChunks->FromMemory.pBuffer);
					break;
				}
			} while (pEntityChunks++, --EntityChunkCount);
		}

		if (PHTTP_SSL_INFO pSslInfo = phr->pSslInfo)
		{
			__nop();
		}

		if (USHORT RequestInfoCount = phr->RequestInfoCount)
		{
			PHTTP_REQUEST_INFO pRequestInfo = phr->pRequestInfo;
			do 
			{
				DbgPrint("\t{%x, %x, %p}\n", pRequestInfo->InfoType, pRequestInfo->InfoLength, pRequestInfo->pInfo);
			} while (pRequestInfo++, --RequestInfoCount);
		}

		Send200(phr->RequestId, buf, cch + len, "text/html", (PVOID)phr->UrlContext);
	}

	virtual void IOCompletionRoutine(CDataPacket* packet, 
		DWORD Code, 
		NTSTATUS status, 
		ULONG_PTR dwNumberOfBytesTransfered, 
		PVOID Pointer)
	{
		DbgPrint("%s<%p>: %.4S: %08x [%x] %p\n", __FUNCTIONW__, this, &Code, status, dwNumberOfBytesTransfered, Pointer);
		
		if (status)
		{
			WCHAR err[0x80];
			if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, 0, status, 0, err, _countof(err), 0))
			{
				DbgPrint("%s\n", err);
			}
		}

		switch (Code)
		{
		case e_recv:
			OnRecv(status, (PHTTP_REQUEST_V2)Pointer);

			switch (status)
			{
			case ERROR_CONNECTION_INVALID:
			case NOERROR:
				Recv(packet);
				break;
			}
			break;

		case e_send:
			if (!Pointer)
			{
				ZwAlertThreadByThreadId((HANDLE)(ULONG_PTR)_M_dwThreadId);
			}
			break;
		}
	}

	ULONG Create(_In_opt_ PCWSTR Name = 0, _In_opt_ PSECURITY_ATTRIBUTES SecurityAttributes = 0)
	{
		HANDLE ReqQueueHandle;
		ULONG hr = HttpCreateRequestQueue(HTTPAPI_VERSION_2, Name, SecurityAttributes, 0, &ReqQueueHandle);
		if (NOERROR == hr)
		{
			DbgPrint("ReqQueueHandle=%p\n", ReqQueueHandle);

			if (NOERROR == (hr = IO_IRP::BindIoCompletion(ReqQueueHandle)))
			{
				Assign(ReqQueueHandle);

				return NOERROR;
			}

			HttpCloseRequestQueue(ReqQueueHandle);
		}

		return hr;
	}

	ULONG Send200(HTTP_REQUEST_ID RequestId, PCSTR body, ULONG len, PCSTR ContentType, PVOID Pointer)
	{
		HTTP_RESPONSE response { {0, HTTPAPI_VERSION_2, 200} };

		response.Headers.KnownHeaders[HttpHeaderContentType].pRawValue = ContentType;
		response.Headers.KnownHeaders[HttpHeaderContentType].RawValueLength = (USHORT)strlen(ContentType) - 1;

		HTTP_DATA_CHUNK dataChunk { HttpDataChunkFromMemory, { {const_cast<PSTR>(body), len } } };
		response.EntityChunkCount = 1;
		response.pEntityChunks = &dataChunk;

		return Send(RequestId, &response, Pointer);
	}

	ULONG Send(HTTP_REQUEST_ID RequestId, PHTTP_RESPONSE response, PVOID Pointer)
	{
		if (IO_IRP* irp = new IO_IRP(this, e_send, 0, Pointer))
		{
			ULONG hr = ERROR_INVALID_HANDLE;

			HANDLE RequestQueueHandle;

			if (LockHandle(RequestQueueHandle))
			{
				hr = HttpSendHttpResponse(RequestQueueHandle, RequestId, 0, response, 0, 0, 0, 0, irp, 0);

				UnlockHandle();
			}

			return irp->CheckErrorCode(hr);
		}

		return ERROR_OUTOFMEMORY;
	}

	ULONG Recv(CDataPacket* packet, HTTP_REQUEST_ID RequestId = HTTP_NULL_ID)
	{
		PHTTP_REQUEST_V2 phr = (PHTTP_REQUEST_V2)packet->getData();

		if (IO_IRP* irp = new IO_IRP(this, e_recv, packet, phr))
		{
			ULONG hr = ERROR_INVALID_HANDLE;

			HANDLE RequestQueueHandle;

			if (LockHandle(RequestQueueHandle))
			{
				hr = HttpReceiveHttpRequest(RequestQueueHandle, RequestId, 
					HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY, phr, packet->getBufferSize(), 0, irp);

				UnlockHandle();
			}

			return irp->CheckErrorCode(hr);
		}

		return ERROR_OUTOFMEMORY;
	}

	ULONG Recv(HTTP_REQUEST_ID RequestId = HTTP_NULL_ID)
	{
		if (CDataPacket* packet = new(0x4000) CDataPacket)
		{
			ULONG dwError = Recv(packet, RequestId);

			packet->Release();

			return dwError;
		}

		return ERROR_OUTOFMEMORY;
	}

	ULONG Bind(HTTP_URL_GROUP_ID UrlGroupId)
	{
		ULONG hr = ERROR_INVALID_HANDLE;

		HTTP_BINDING_INFO bi = {{TRUE}};

		if (LockHandle(bi.RequestQueueHandle))
		{
			hr = HttpSetUrlGroupProperty(UrlGroupId, HttpServerBindingProperty, &bi, sizeof(bi));
			UnlockHandle();
		}

		return hr;
	}

	ULONG Shutdown()
	{
		ULONG hr = ERROR_INVALID_HANDLE;

		HANDLE RequestQueueHandle;

		if (LockHandle(RequestQueueHandle))
		{
			hr = HttpShutdownRequestQueue(RequestQueueHandle);
			UnlockHandle();
		}

		return hr;
	}
};

HRESULT CreateSG(_In_ HttpRequest* req, 
				 _Out_ PHTTP_SERVER_SESSION_ID pServerSessionId, 
				 _Out_ PHTTP_URL_GROUP_ID pG1, 
				 _Out_ PHTTP_URL_GROUP_ID pG2)
{
	HRESULT hr;

	HTTP_SERVER_SESSION_ID ServerSessionId;

	if (NOERROR == (hr = HttpCreateServerSession(HTTPAPI_VERSION_2, &ServerSessionId, 0)))
	{
		DbgPrint("ServerSessionId=%016I64X\n", ServerSessionId);

		*pServerSessionId = ServerSessionId;

		HTTP_URL_GROUP_ID UrlGroupId;

		if (NOERROR == HttpCreateUrlGroup(ServerSessionId, &UrlGroupId, 0))
		{
			DbgPrint("\tUrlGroupId=%016I64X\n", UrlGroupId);

			if (NOERROR == HttpAddUrlToUrlGroup(UrlGroupId, 
				L"http://127.0.0.1:1111/aaaa/", (HTTP_URL_CONTEXT)"** 1111", 0) &&
				NOERROR == HttpAddUrlToUrlGroup(UrlGroupId, 
				L"http://127.0.0.1:2222/bbbb/", (HTTP_URL_CONTEXT)"** 2222", 0) &&
				NOERROR == req->Bind(UrlGroupId))
			{
				*pG1 = UrlGroupId;
			}
			else
			{
				HttpCloseUrlGroup(UrlGroupId);
			}
		}

		if (NOERROR == HttpCreateUrlGroup(ServerSessionId, &UrlGroupId, 0))
		{
			DbgPrint("\tUrlGroupId=%016I64X\n", UrlGroupId);

			if (NOERROR == HttpAddUrlToUrlGroup(UrlGroupId, 
				L"http://127.0.0.1:4310/stop/", 0, 0) &&
				NOERROR == req->Bind(UrlGroupId))
			{
				*pG2 = UrlGroupId;
			}
			else
			{
				HttpCloseUrlGroup(UrlGroupId);
			}
		}

		HTTP_LOGGING_INFO li {
			{TRUE}, HTTP_LOGGING_FLAG_USE_UTF8_CONVERSION
		};

		ULONG cch = 0;
		while (cch = ExpandEnvironmentStringsW(L"%windir%\\temp", const_cast<PWSTR>(li.DirectoryName), cch))
		{
			if (li.DirectoryName)
			{
				li.DirectoryNameLength = (USHORT)(cch - 1) * sizeof(WCHAR);
				li.Format = HttpLoggingTypeW3C;
				li.RolloverSize = 0x180000;
				li.Fields = HTTP_LOG_FIELD_DATE|HTTP_LOG_FIELD_TIME|HTTP_LOG_FIELD_CLIENT_IP;

				HttpSetServerSessionProperty(ServerSessionId, HttpServerLoggingProperty, &li, sizeof(li));
				break;
			}

			li.DirectoryName = (PWSTR)alloca(cch * sizeof(WCHAR));
		}
	}

	return hr;
}

int http_test()
{
	HRESULT hr = HttpInitialize( 
		HTTPAPI_VERSION_2,
		HTTP_INITIALIZE_SERVER,    // Flags
		NULL                       // Reserved
		);

	if (NOERROR == hr)
	{
		if (HttpRequest* req = new HttpRequest)
		{
			WCHAR name[0x20];
			swprintf_s(name, _countof(name), L"Request[#%x]", GetCurrentProcessId());

			if (NOERROR == (hr = req->Create(name)))
			{
				HTTP_URL_GROUP_ID G1 = 0, G2 = 0;
				HTTP_SERVER_SESSION_ID ServerSessionId = 0;

				if (NOERROR == CreateSG(req, &ServerSessionId, &G1, &G2))
				{
					ULONG n = 2;
					do 
					{
						req->Recv();
					} while (--n);

					ZwWaitForAlertByThreadId(req, 0);

					if (G2)
					{
						HttpCloseUrlGroup(G2);
					}

					if (G1)
					{
						HttpCloseUrlGroup(G1);
					}

					HttpCloseServerSession(ServerSessionId);
				}
			}

			req->Shutdown();
			req->Release();
		}
	
		HttpTerminate(HTTP_INITIALIZE_SERVER, 0);
	}
		
	return hr;
}

#include "../INC/initterm.h"

void IO_RUNDOWN::RundownCompleted()
{
	destroyterm();
	ExitProcess(0);
}

void CALLBACK ep(void*)
{
	initterm();
	InitPrintf();
	http_test();
	IO_RUNDOWN::g_IoRundown.BeginRundown();
}

_NT_END