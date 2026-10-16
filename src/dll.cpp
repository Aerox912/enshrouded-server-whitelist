#include "runtime.hpp"
#include "file_hash.hpp"
#include <filesystem>
#include <fstream>
#include <cstdio>
#include <iterator>
namespace {
HMODULE self=nullptr;HANDLE log_file=INVALID_HANDLE_VALUE;
using GetServer=void*(*)();using EndAuth=void(*)(void*,std::uint64_t);
GetServer steam_server=nullptr;EndAuth end_auth=nullptr;
bool cleanup_rejected(std::uint64_t steam_id){
 auto server=steam_server();if(!server)return false;
 end_auth(server,steam_id);return true;
}
bool resolve_cleanup(){
 auto steam=GetModuleHandleW(L"steam_api64.dll");
 if(!steam||!esm::admission::verify_file(esm::admission::module_path(steam),"e6d9bafb9a41e42fba7b21553db49f8719027af3f0deb23ff86cfc44d60e776d"))return false;
 auto getter=GetProcAddress(steam,"SteamAPI_SteamGameServer_v015");
 auto end=GetProcAddress(steam,"SteamAPI_ISteamGameServer_EndAuthSession");
 if(!getter||!end)return false;
 static_assert(sizeof(getter)==sizeof(steam_server)&&sizeof(end)==sizeof(end_auth));
 std::memcpy(&steam_server,&getter,sizeof(getter));std::memcpy(&end_auth,&end,sizeof(end));
 return true;
}
void log(const char* message){
 SYSTEMTIME now{};GetSystemTime(&now);char line[320]{};
 auto n=sprintf_s(line,"%04u-%02u-%02uT%02u:%02u:%02uZ pid=%lu %s\r\n",now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond,GetCurrentProcessId(),message);
 if(n>0){DWORD written=0;WriteFile(log_file,line,static_cast<DWORD>(n),&written,nullptr);FlushFileBuffers(log_file);}
}
bool startup_profile(){
 auto game=GetModuleHandleW(nullptr);auto b=reinterpret_cast<unsigned char*>(game);
 auto dos=reinterpret_cast<IMAGE_DOS_HEADER*>(b);auto nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(b+dos->e_lfanew);
 const auto tls=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
 if(tls.VirtualAddress){
  auto directory=reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(b+tls.VirtualAddress);
  if(directory->AddressOfCallBacks&&*reinterpret_cast<void**>(directory->AddressOfCallBacks)){log("STARTUP PROFILE REFUSED: executable TLS callback");return false;}
 }
 const auto root=std::filesystem::path(esm::admission::module_path(game)).parent_path();
 if(!esm::admission::verify_file((root/L"steam_api64.dll").wstring(),"e6d9bafb9a41e42fba7b21553db49f8719027af3f0deb23ff86cfc44d60e776d"))return false;
 log("STARTUP PROFILE VERIFIED: entrypoint held; no EXE TLS callbacks; Steam API pinned");
 return true;
}
bool debugger_commit(void* site,const void* replacement,const void* expected,size_t size){
 if(!IsDebuggerPresent()||size!=5)return false;
 const ULONG_PTR args[]{reinterpret_cast<ULONG_PTR>(site),reinterpret_cast<ULONG_PTR>(replacement),reinterpret_cast<ULONG_PTR>(expected),size};
 // No game-code write occurs in this thread. The owned debugger receives the
 // exception with all target threads stopped, validates and writes the CALL,
 // restores page protection and flushes the cache before continuing us.
 RaiseException(0xe0e5a001,0,4,args);
 if(std::memcmp(site,replacement,size))return false;
 log("COMMIT VERIFIED: owned debugger installed CALL with all target threads stopped");
 return true;
}
}
extern "C" __declspec(dllexport) DWORD WINAPI EsmAdmissionInitialize(void* primary_id) {
 try {
  // Reject late/in-process loads. Installation is supported only while the
  // launcher's owned primary thread is suspended at the untouched EXE entry.
  const auto id=reinterpret_cast<std::uintptr_t>(primary_id);
  if(!id||id>MAXDWORD||id==GetCurrentThreadId())return 0;
  auto primary=OpenThread(THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,FALSE,static_cast<DWORD>(id));
  if(!primary)return 0;
  bool gate=false;
  if(GetProcessIdOfThread(primary)==GetCurrentProcessId()){
   auto previous=SuspendThread(primary);
   if(previous!=DWORD(-1)){
    CONTEXT context{};context.ContextFlags=CONTEXT_CONTROL;
    auto base=reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    auto dos=reinterpret_cast<IMAGE_DOS_HEADER*>(base);auto nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
    gate=previous==1&&GetThreadContext(primary,&context)&&context.Rip==reinterpret_cast<DWORD64>(base+nt->OptionalHeader.AddressOfEntryPoint);
    if(ResumeThread(primary)!=previous+1)gate=false;
   }
  }
  CloseHandle(primary);if(!gate)return 0;
  const auto root=std::filesystem::path(esm::admission::module_path(self)).parent_path();
  const auto config=root/L"esm-admission.txt";
  std::error_code error;auto size=std::filesystem::file_size(config,error);
  if(error||!size||size>512*19)return 0;
  std::ifstream file(config,std::ios::binary);if(!file)return 0;
  const std::string text((std::istreambuf_iterator<char>(file)),std::istreambuf_iterator<char>());
  if(text.size()!=size)return 0;
  log_file=CreateFileW((root/L"esm-admission.log").c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(log_file==INVALID_HANDLE_VALUE)return 0;
  if(!startup_profile()||!resolve_cleanup())return 0;
  if(!esm::admission::install(GetModuleHandleW(nullptr),text,log,debugger_commit,cleanup_rejected)){log("ESM ADMISSION INIT FAILED; launcher must refuse startup");return 0;}
  return 0x45534d01;
 }catch(...){return 0;}
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH)self=module;return TRUE;}
