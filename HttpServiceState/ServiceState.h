#pragma once

#define _DBG_

struct HTTP_URL_GROUP {
	/*00*/ HTTP_URL_GROUP* next;
	/*08*/ HTTP_URL_GROUP_ID UrlGroupId;	// <- HttpCreateUrlGroup
	/*10*/ HTTP_STATE_INFO state;
	/*18*/ HTTP_OPAQUE_ID QueueId;			// match to HTTP_REQUEST_QUEUE::QueueId
	/*20*/ USHORT QueueNameLen;
	/*24*/ ULONG UrlCount;
	/*28*/ PCWSTR QueueName;				// HttpSetUrlGroupProperty(UrlGroupId, HttpServerBindingProperty)
	/*30*/ PCWSTR RegisteredUrls;
	/*38*/ HTTP_BANDWIDTH_LIMIT_INFO bli;
	/*40*/ HTTP_CONNECTION_LIMIT_INFO cli;
	/*48*/ HTTP_LOGGING_TYPE Format;		// Specifies the format for the log files.
	/*4c*/ USHORT DirectoryNameLength;		// Length must be in number of bytes.
	/*50*/ PCWSTR DirectoryName;			// Log file directory must be a fully qualified path.
	/*58*/ HTTP_TIMEOUT_LIMIT_INFO tli;
	/*6c*/ UCHAR unk[0xc]; // ???
	/*78*/ HTTP_PROPERTY_FLAGS AuthFlags;
	/*7c*/ ULONG AuthSchemes;
	/*80*/ BOOLEAN ReceiveMutualAuth;
	/*81*/ BOOLEAN ReceiveContextHandle;
	/*82*/ BOOLEAN DisableNTLMCredentialCaching;
	/*83*/ UCHAR   ExFlags;
	/*84*/ USHORT  DigestDomainNameLength;
	/*86*/ USHORT  DigestRealmNameLength;
	/*88*/ USHORT  BasicRealmNameLength;
	/*90*/ PWSTR   DigestDomainName;
	/*98*/ PWSTR   DigestRealmName;
	/*a0*/ PWSTR   BasicRealmName;
	/*a8*/ HTTP_PROPERTY_FLAGS HardFlags;
	/*ac*/ HTTP_AUTHENTICATION_HARDENING_LEVELS Hardening;
	/*B0*/ HTTP_PROTECTION_LEVEL_INFO pli;
};

#ifdef _DBG_

C_ASSERT(sizeof(HTTP_TIMEOUT_LIMIT_INFO)==0x14);

C_ASSERT(offsetof(HTTP_URL_GROUP, QueueNameLen) == 0x20);
C_ASSERT(offsetof(HTTP_URL_GROUP, UrlCount) == 0x24);
C_ASSERT(offsetof(HTTP_URL_GROUP, RegisteredUrls) == 0x30);
C_ASSERT(offsetof(HTTP_URL_GROUP, Format) == 0x48);
C_ASSERT(offsetof(HTTP_URL_GROUP, tli) == 0x58);
C_ASSERT(offsetof(HTTP_URL_GROUP, AuthFlags) == 0x78);
C_ASSERT(offsetof(HTTP_URL_GROUP, DigestDomainName) == 0x90);
C_ASSERT(offsetof(HTTP_URL_GROUP, pli) == 0xb0);

#endif

struct HTTP_SERVER_SESSION {
	/*00*/ HTTP_SERVER_SESSION* next;
	/*08*/ HTTP_URL_GROUP* firstGroup;
	/*10*/ HTTP_SERVER_SESSION_ID ServerSessionId;	// <- HttpCreateServerSession
	/*18*/ HTTPAPI_VERSION version;
	/*1C*/ HTTP_STATE_INFO state;
	/*24*/ HTTP_BANDWIDTH_LIMIT_INFO bli;
	/*2C*/ ULONG LoggingFlags; // ?!
	/*30*/ HTTP_LOGGING_TYPE Format;				// Specifies the format for the log files.
	/*34*/ USHORT DirectoryNameLength;				// Length must be in number of bytes.
	/*38*/ PCWSTR DirectoryName;					// Log file directory must be a fully qualified path.
	/*40*/ HTTP_TIMEOUT_LIMIT_INFO tli;
	/*54*/ UCHAR unk[0xc]; // ???
	/*60*/ HTTP_PROPERTY_FLAGS AuthFlags;
	/*64*/ ULONG AuthSchemes;
	/*68*/ BOOLEAN ReceiveMutualAuth;
	/*69*/ BOOLEAN ReceiveContextHandle;
	/*6a*/ BOOLEAN DisableNTLMCredentialCaching;
	/*6b*/ UCHAR   ExFlags;
	/*6c*/ USHORT  DigestDomainNameLength;
	/*6e*/ USHORT  DigestRealmNameLength;
	/*70*/ USHORT  BasicRealmNameLength;
	/*78*/ PWSTR   DigestDomainName;
	/*80*/ PWSTR   DigestRealmName;
	/*88*/ PWSTR   BasicRealmName;
	/*90*/ HTTP_PROPERTY_FLAGS HardFlags;
	/*94*/ HTTP_AUTHENTICATION_HARDENING_LEVELS Hardening;
};

#ifdef _DBG_

C_ASSERT(offsetof(HTTP_SERVER_SESSION, bli) == 0x24);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, Format) == 0x30);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, DirectoryName) == 0x38);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, tli) == 0x40);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, AuthFlags) == 0x60);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, DigestDomainName) == 0x78);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, HardFlags) == 0x90);
C_ASSERT(offsetof(HTTP_SERVER_SESSION, Hardening) == 0x94);

#endif

struct HTTP_REQUEST_QUEUE {
	/*00*/ HTTP_REQUEST_QUEUE* next;
	/*08*/ HTTPAPI_VERSION version;
	/*0c*/ HTTP_ENABLED_STATE state;
	/*10*/ HTTP_503_RESPONSE_VERBOSITY rb503;
	/*18*/ HTTP_OPAQUE_ID QueueId;
	/*20*/ PCWSTR Name;			// HttpCreateRequestQueue
	/*28*/ USHORT NameLength;	// Length must be in number of bytes.
	/*2c*/ ULONG QueueLength;	// MaxRequests <- HttpServerQueueLengthProperty
	/*30*/ ULONG ActiveProcessCount;
	/*38*/ HANDLE* rgProcessesId;
	/*40*/ HANDLE ControllerProcessId;
	/*48*/ HANDLE ControllerProcessTag;
	/*50*/ HANDLE* rgProcessTag;
};

#ifdef _DBG_

C_ASSERT(offsetof(HTTP_REQUEST_QUEUE, QueueLength) == 0x2c);
C_ASSERT(offsetof(HTTP_REQUEST_QUEUE, rgProcessTag) == 0x50);

#endif

struct HTTP_SERVICE_STATE {
	HTTP_SERVER_SESSION* firstSession;
	HTTP_REQUEST_QUEUE* firstQueue;
};

struct HTTP_MGMT_ROOT_INFO {
	enum {
		UlpReadAndCopyServiceState,
		UlpReadAndCopyCacheEntries,
		UlMgmtFlushCache, // 2 - AdminCheck
		UlMgmtFlushLogFileBuffers, // 3  - AdminCheck
		UlMgmtEnableFastIo, // ?!
	} code;
	UNICODE_STRING Name; // ?!
};

#ifdef _DBG_
C_ASSERT(sizeof(HTTP_MGMT_ROOT_INFO)== 0x18);
#endif
