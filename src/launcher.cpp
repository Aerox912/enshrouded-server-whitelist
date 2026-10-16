#include "file_hash.hpp"
#include <tlhelp32.h>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <vector>
#ifndef ESM_ADMISSION_LAUNCH_TESTING
#include "guard_artifact.hpp"
#endif
namespace {
struct Handle {
 HANDLE h=nullptr;
 explicit Handle(HANDLE value=nullptr):h(value){}
 ~Handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
 Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
void require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
std::uintptr_t remote_module(DWORD pid,const std::wstring& name,bool full){
 Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid));
 require(snapshot.h!=INVALID_HANDLE_VALUE,"module snapshot failed");
 MODULEENTRY32W e{};e.dwSize=sizeof(e);
 if(Module32FirstW(snapshot.h,&e))do {
  if(!_wcsicmp(full?e.szExePath:e.szModule,name.c_str()))return reinterpret_cast<std::uintptr_t>(e.modBaseAddr);
 }while(Module32NextW(snapshot.h,&e));
 return 0;
}
void* remote_system_function(DWORD pid,HANDLE process,const wchar_t* module,const char* function){
 auto pointer=GetProcAddress(GetModuleHandleW(module),function);require(pointer!=nullptr,"system export missing");
 HMODULE owner=nullptr;
 require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,reinterpret_cast<LPCWSTR>(pointer),&owner)!=0,"system export owner missing");
 auto remote=remote_module(pid,std::filesystem::path(esm::admission::module_path(owner)).filename().wstring(),false);
 require(remote!=0,"remote system module missing");
 auto address=remote+(reinterpret_cast<std::uintptr_t>(pointer)-reinterpret_cast<std::uintptr_t>(owner));
 std::array<unsigned char,24> code{};SIZE_T n=0;
 require(ReadProcessMemory(process,reinterpret_cast<void*>(address),code.data(),code.size(),&n)&&n==code.size()&&!std::memcmp(code.data(),pointer,code.size()),"remote system export differs");
 return reinterpret_cast<void*>(address);
}
DWORD run_thread(HANDLE process,void* start,void* argument){
 Handle thread(CreateRemoteThread(process,nullptr,0,reinterpret_cast<LPTHREAD_START_ROUTINE>(start),argument,0,nullptr));
 require(thread.h!=nullptr,"guard worker creation failed");
 require(WaitForSingleObject(thread.h,15000)==WAIT_OBJECT_0,"guard worker did not complete");
 DWORD result=0;require(GetExitCodeThread(thread.h,&result)!=0,"guard result unavailable");return result;
}
DWORD run_guard(PROCESS_INFORMATION& pi,void* start,bool& debugging){
 require(DebugActiveProcess(pi.dwProcessId)!=0,"guard debugger attach failed");debugging=true;
 DWORD worker_id=0;
 Handle worker(CreateRemoteThread(pi.hProcess,nullptr,0,reinterpret_cast<LPTHREAD_START_ROUTINE>(start),reinterpret_cast<void*>(static_cast<std::uintptr_t>(pi.dwThreadId)),0,&worker_id));
 require(worker.h!=nullptr,"guard worker creation failed");
 const auto deadline=GetTickCount64()+15000;bool patched=false,finished=false,initial_break=false;DWORD result=0;
 while(!finished&&GetTickCount64()<deadline){
  DEBUG_EVENT event{};
  if(!WaitForDebugEvent(&event,250)){require(GetLastError()==ERROR_SEM_TIMEOUT,"guard debug wait failed");continue;}
  require(event.dwProcessId==pi.dwProcessId,"unexpected debugger target");DWORD disposition=DBG_CONTINUE;
  if(event.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT&&event.u.CreateProcessInfo.hFile)CloseHandle(event.u.CreateProcessInfo.hFile);
  if(event.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT&&event.u.LoadDll.hFile)CloseHandle(event.u.LoadDll.hFile);
  if(event.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)throw std::runtime_error("server exited during guard initialization");
  if(event.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT&&event.dwThreadId==worker_id){finished=true;result=event.u.ExitThread.dwExitCode;}
  if(event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){
   const auto& info=event.u.Exception;const auto& exception=info.ExceptionRecord;
   if(info.dwFirstChance&&exception.ExceptionCode==0xe0e5a001&&event.dwThreadId==worker_id){
    require(!patched&&exception.NumberParameters>=4&&exception.ExceptionInformation[3]==5,"invalid or repeated guard commit");
    const auto site=exception.ExceptionInformation[0];
#ifndef ESM_ADMISSION_LAUNCH_TESTING
    auto base=remote_module(pi.dwProcessId,L"enshrouded_server.exe",false);
    require(base&&site==base+0x9cd0d5,"commit is outside the verified callback CALL");
#endif
    std::array<unsigned char,5> expected{},replacement{},current{};
    auto read=[&](ULONG_PTR address,void* data,SIZE_T bytes){SIZE_T n=0;require(ReadProcessMemory(pi.hProcess,reinterpret_cast<void*>(address),data,bytes,&n)&&n==bytes,"commit data unreadable");};
    read(exception.ExceptionInformation[1],replacement.data(),5);read(exception.ExceptionInformation[2],expected.data(),5);read(site,current.data(),5);
    require(current==expected&&replacement[0]==0xe8,"commit preimage or CALL differs");
#ifndef ESM_ADMISSION_LAUNCH_TESTING
    require(expected==std::array<unsigned char,5>{0xe8,0x06,0x7f,0x00,0x00},"unexpected original CALL");
#endif
    // Windows stops every target thread for this outstanding debug event.
    // Reject any instruction pointer inside the bytes about to be changed.
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0));require(snapshot.h!=INVALID_HANDLE_VALUE,"commit thread snapshot failed");
    THREADENTRY32 thread{};thread.dwSize=sizeof(thread);require(Thread32First(snapshot.h,&thread)!=0,"commit threads unavailable");
    do {if(thread.th32OwnerProcessID!=pi.dwProcessId)continue;
     Handle h(OpenThread(THREAD_GET_CONTEXT,FALSE,thread.th32ThreadID));CONTEXT context{};context.ContextFlags=CONTEXT_CONTROL;
     require(h.h&&GetThreadContext(h.h,&context),"commit thread context unavailable");
     require(context.Rip<site||context.Rip>=site+5,"thread is inside callback patch");
    }while(Thread32Next(snapshot.h,&thread));
#ifdef ESM_ADMISSION_LAUNCH_TESTING
    // A real background worker in the fixture must stop too, not just main.
    require(exception.NumberParameters==5,"fixture heartbeat missing");LONG64 before=0,after=0;
    read(exception.ExceptionInformation[4],&before,sizeof(before));Sleep(100);read(exception.ExceptionInformation[4],&after,sizeof(after));
    require(before>0&&before==after,"debugger did not quiesce background worker");
#endif
    DWORD previous=0,ignored=0;SIZE_T written=0;
    require(VirtualProtectEx(pi.hProcess,reinterpret_cast<void*>(site),5,PAGE_EXECUTE_READWRITE,&previous)!=0,"commit page protection failed");
    require(WriteProcessMemory(pi.hProcess,reinterpret_cast<void*>(site),replacement.data(),5,&written)&&written==5,"commit write failed");
    require(VirtualProtectEx(pi.hProcess,reinterpret_cast<void*>(site),5,previous,&ignored)&&FlushInstructionCache(pi.hProcess,reinterpret_cast<void*>(site),5),"commit page/cache restore failed");
    read(site,current.data(),5);require(current==replacement,"commit readback differs");patched=true;
   }else if(info.dwFirstChance&&exception.ExceptionCode==EXCEPTION_BREAKPOINT&&!initial_break){
    MEMORY_BASIC_INFORMATION memory{};
    require(VirtualQueryEx(pi.hProcess,exception.ExceptionAddress,&memory,sizeof(memory))==sizeof(memory)&&reinterpret_cast<std::uintptr_t>(memory.AllocationBase)==remote_module(pi.dwProcessId,L"ntdll.dll",false),"unexpected guard attach breakpoint");initial_break=true;
   }else disposition=DBG_EXCEPTION_NOT_HANDLED;
  }
  require(ContinueDebugEvent(event.dwProcessId,event.dwThreadId,disposition)!=0,"guard debug continuation failed");
 }
 require(finished,"guard worker did not complete");
 require(result!=0x45534d01||patched,"guard claimed ready without debugger commit");
 require(DebugActiveProcessStop(pi.dwProcessId)!=0,"guard debug detach failed");debugging=false;
 return result;
}
}
int wmain(int argc,wchar_t** argv){
 PROCESS_INFORMATION pi{};bool committed=false,debugging=false;
 Handle job(CreateJobObjectW(nullptr,nullptr));
 try {
  require(argc==3,"usage: esm_admission_launcher.exe SERVER_EXE GUARD_DLL");
  auto exe=std::filesystem::absolute(argv[1]).lexically_normal();
  auto dll=std::filesystem::absolute(argv[2]).lexically_normal();
  Handle exe_lock(CreateFileW(exe.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
  Handle dll_lock(CreateFileW(dll.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
  require(exe_lock.h!=INVALID_HANDLE_VALUE&&dll_lock.h!=INVALID_HANDLE_VALUE,"server or guard missing/locked");
#ifndef ESM_ADMISSION_LAUNCH_TESTING
  require(esm::admission::verify_file(exe.wstring(),esm::admission::game_hash),"unsupported server executable");
  require(esm::admission::verify_file(dll.wstring(),expected_guard_hash),"unrecognized admission guard artifact");
#endif
  // Inspect only the export table locally. Never execute guard code in launcher.
  auto local=LoadLibraryExW(dll.c_str(),nullptr,DONT_RESOLVE_DLL_REFERENCES);
  require(local!=nullptr,"guard export image unreadable");
  auto init=GetProcAddress(local,"EsmAdmissionInitialize");
  auto offset=reinterpret_cast<std::uintptr_t>(init)-reinterpret_cast<std::uintptr_t>(local);
  FreeLibrary(local);require(init!=nullptr,"guard initialization export missing");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  require(job.h&&SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits)),"startup containment unavailable");
  STARTUPINFOW si{};si.cb=sizeof(si);si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
  auto command=L"\""+exe.wstring()+L"\"";
  require(CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS|CREATE_NEW_CONSOLE,nullptr,exe.parent_path().c_str(),&si,&pi)!=0,"owned server creation failed");
  debugging=true;
  require(AssignProcessToJobObject(job.h,pi.hProcess)!=0,"startup containment assignment failed");
  auto deadline=GetTickCount64()+15000;bool loader_ready=false,initial_break_seen=false;
  void* entry=nullptr;unsigned char saved_entry=0;
  auto write_entry=[&](unsigned char byte){
   DWORD previous=0,ignored=0;SIZE_T written=0;
   require(VirtualProtectEx(pi.hProcess,entry,1,PAGE_EXECUTE_READWRITE,&previous)!=0,"entry protection failed");
   require(WriteProcessMemory(pi.hProcess,entry,&byte,1,&written)&&written==1,"entry breakpoint write failed");
   require(VirtualProtectEx(pi.hProcess,entry,1,previous,&ignored)&&FlushInstructionCache(pi.hProcess,entry,1),"entry protection restore failed");
  };
  while(!loader_ready&&GetTickCount64()<deadline){
   DEBUG_EVENT event{};
   if(!WaitForDebugEvent(&event,500)){require(GetLastError()==ERROR_SEM_TIMEOUT,"debug event failed");continue;}
   DWORD disposition=DBG_CONTINUE;
   if(event.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){
    if(event.u.CreateProcessInfo.hFile)CloseHandle(event.u.CreateProcessInfo.hFile);
    entry=reinterpret_cast<void*>(event.u.CreateProcessInfo.lpStartAddress);SIZE_T read=0;
    require(entry&&ReadProcessMemory(pi.hProcess,entry,&saved_entry,1,&read)&&read==1&&saved_entry!=0xcc,"original entry unavailable");
    write_entry(0xcc);
   }
   if(event.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT&&event.u.LoadDll.hFile)CloseHandle(event.u.LoadDll.hFile);
   if(event.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)throw std::runtime_error("server exited before guard");
   if(event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){
    auto& exception=event.u.Exception;
    if(exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT&&event.dwThreadId==pi.dwThreadId&&exception.dwFirstChance){
     if(exception.ExceptionRecord.ExceptionAddress==entry){
      require(initial_break_seen,"entry reached before loader breakpoint");
      write_entry(saved_entry);
      CONTEXT context{};context.ContextFlags=CONTEXT_CONTROL;
      require(GetThreadContext(pi.hThread,&context)!=0,"entry context unavailable");
      context.Rip=reinterpret_cast<DWORD64>(entry);
      require(SetThreadContext(pi.hThread,&context)!=0,"entry context restore failed");
      require(SuspendThread(pi.hThread)!=DWORD(-1),"primary thread could not be held");loader_ready=true;
     }else {
      require(!initial_break_seen,"unexpected additional startup breakpoint");
      MEMORY_BASIC_INFORMATION memory{};
      require(VirtualQueryEx(pi.hProcess,exception.ExceptionRecord.ExceptionAddress,&memory,sizeof(memory))==sizeof(memory)&&
       reinterpret_cast<std::uintptr_t>(memory.AllocationBase)==remote_module(pi.dwProcessId,L"ntdll.dll",false),"unexpected startup breakpoint owner");
      initial_break_seen=true;
     }
    }else disposition=DBG_EXCEPTION_NOT_HANDLED;
   }
   require(ContinueDebugEvent(event.dwProcessId,event.dwThreadId,disposition)!=0,"debug continuation failed");
  }
  require(loader_ready,"loader startup timeout");
  require(DebugActiveProcessStop(pi.dwProcessId)!=0,"debug detach failed");debugging=false;
  auto loader=remote_system_function(pi.dwProcessId,pi.hProcess,L"kernel32.dll","LoadLibraryW");
  auto bytes=(dll.wstring().size()+1)*sizeof(wchar_t);
  auto path=VirtualAllocEx(pi.hProcess,nullptr,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);require(path!=nullptr,"guard path allocation failed");
  SIZE_T written=0;require(WriteProcessMemory(pi.hProcess,path,dll.c_str(),bytes,&written)&&written==bytes,"guard path copy failed");
  run_thread(pi.hProcess,loader,path);
  require(VirtualFreeEx(pi.hProcess,path,0,MEM_RELEASE)!=0,"guard path cleanup failed");
  auto remote=remote_module(pi.dwProcessId,dll.wstring(),true);require(remote!=0,"guard DLL not loaded");
  require(run_guard(pi,reinterpret_cast<void*>(remote+offset),debugging)==0x45534d01,"guard initialization rejected startup");
  limits.BasicLimitInformation.LimitFlags=0;
  require(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=0,"startup containment release failed");
  require(ResumeThread(pi.hThread)==1,"primary thread resume state differs");committed=true;
  std::printf("{\"state\":\"guard-ready-primary-resumed\",\"pid\":%lu}\n",pi.dwProcessId);
 }catch(const std::exception& error){
  if(pi.hProcess) {TerminateProcess(pi.hProcess,90);if(debugging)DebugActiveProcessStop(pi.dwProcessId);WaitForSingleObject(pi.hProcess,5000);}
  std::fprintf(stderr,"START REFUSED: %s (win32=%lu)\n",error.what(),GetLastError());
 }
 if(pi.hThread)CloseHandle(pi.hThread);if(pi.hProcess)CloseHandle(pi.hProcess);
 return committed?0:1;
}
