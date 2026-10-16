#include <windows.h>
#include <cstdio>
#include <array>
#include <cstring>
namespace {
volatile LONG64 heartbeat=0;
DWORD WINAPI worker(void*){for(;;){InterlockedIncrement64(&heartbeat);SwitchToThread();}}
}
extern "C" __declspec(dllexport) DWORD WINAPI EsmAdmissionInitialize(void*) {
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
 FILE* entered=nullptr;fopen_s(&entered,"guard-entered.txt","wb");if(!entered)return 0;
 std::fprintf(entered,"%lu",GetCurrentProcessId());fclose(entered);
 if(GetFileAttributesW(L"entry-ran.txt")!=INVALID_FILE_ATTRIBUTES)return 0;
 if(GetFileAttributesW(L"crash-init.txt")!=INVALID_FILE_ATTRIBUTES){TerminateProcess(GetCurrentProcess(),94);return 0;}
 if(GetFileAttributesW(L"hang-init.txt")!=INVALID_FILE_ATTRIBUTES)Sleep(30000);
 if(GetFileAttributesW(L"reject-init.txt")!=INVALID_FILE_ATTRIBUTES)return 0;
 if(GetFileAttributesW(L"no-commit.txt")==INVALID_FILE_ATTRIBUTES){
  auto thread=CreateThread(nullptr,0,worker,nullptr,0,nullptr);if(!thread)return 0;CloseHandle(thread);
  while(!heartbeat)SwitchToThread();
  std::array<unsigned char,5> site{0xe8,1,2,3,4},expected=site,replacement{0xe8,5,6,7,8};
  if(GetFileAttributesW(L"bad-patch.txt")!=INVALID_FILE_ATTRIBUTES)expected[1]=0xff;
  ULONG_PTR args[]{reinterpret_cast<ULONG_PTR>(site.data()),reinterpret_cast<ULONG_PTR>(replacement.data()),reinterpret_cast<ULONG_PTR>(expected.data()),5,reinterpret_cast<ULONG_PTR>(&heartbeat)};
  RaiseException(0xe0e5a001,0,5,args);
  if(site!=replacement)return 0;
  if(GetFileAttributesW(L"post-commit-reject.txt")!=INVALID_FILE_ATTRIBUTES)return 0;
 }
 auto f=CreateFileW(L"guard-ready.txt",GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,0,nullptr);
 if(f==INVALID_HANDLE_VALUE)return 0;
 CloseHandle(f);return 0x45534d01;
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}
