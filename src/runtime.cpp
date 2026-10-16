#include "runtime.hpp"
#include "policy.hpp"
#include "file_hash.hpp"
#include "native_guards.hpp"
#include <atomic>
#include <cstdio>
#include <limits>
namespace esm::admission {
namespace {
Policy policy;Logger audit=nullptr;std::atomic<bool> attempted=false;
using Queue=bool(*)(void*,const Event*,std::uint64_t);
Queue original_queue=nullptr;
RejectedSessionCleanup close_rejected_session=nullptr;
bool filter_queue(void* queue,const Event* native,std::uint64_t deadline){
 // Runs only at the game's registered Steam ValidateAuthTicketResponse producer.
 // Native removal closes transport, but only ends Steam authentication for
 // peers in state 2. A policy-denied success remains pending (state 1), so end
 // that Steam session here before forwarding the native rejection event.
 Event event=*native;const bool denied=policy.filter(event);
 if(denied){
  std::uint64_t id=0;std::memcpy(&id,native->data()+8,8);
  const bool ended=close_rejected_session(id);
  char line[160]{};sprintf_s(line,"ESM ADMISSION %s steam=%llu",ended?"STEAM_AUTH_ENDED":"STEAM_AUTH_CLEANUP_FAILED",static_cast<unsigned long long>(id));audit(line);
 }
 if(event[0]==19&&audit){
  std::uint64_t id=0;std::uint32_t response=0;std::memcpy(&id,native->data()+8,8);std::memcpy(&response,native->data()+16,4);
  char line[160]{};sprintf_s(line,"ESM ADMISSION %s steam=%llu steam_response=%u",denied?"DENY":(response?"STEAM_FAILURE":"ALLOW"),static_cast<unsigned long long>(id),response);audit(line);
 }
 return original_queue(queue,&event,deadline);
}
bool install_startup_call(unsigned char* site,void* callback,Commit commit){
 // Prepare without changing executable game code. The debugger commits the
 // CALL only while every target thread is stopped at our explicit exception.
 // Retain the leaf relay until process exit; it needs no unwind frame.
 constexpr std::uintptr_t granularity=65536;
 const auto source=reinterpret_cast<std::uintptr_t>(site);
 const auto first=(source+granularity)&~(granularity-1);
 unsigned char* relay=nullptr;
 for(std::uintptr_t at=first;at-source<0x7fff0000;at+=granularity){
  MEMORY_BASIC_INFORMATION memory{};
  if(VirtualQuery(reinterpret_cast<void*>(at),&memory,sizeof(memory))!=sizeof(memory))return false;
  if(memory.State==MEM_FREE){relay=static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(at),4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(relay)break;}
  else {const auto end=reinterpret_cast<std::uintptr_t>(memory.BaseAddress)+memory.RegionSize;if(end>at)at=((end+granularity-1)&~(granularity-1))-granularity;}
 }
 if(!relay)return false;
 std::array<unsigned char,14> jump{0xff,0x25};std::memcpy(jump.data()+6,&callback,8);std::memcpy(relay,jump.data(),jump.size());
 DWORD old=0;
 if(!VirtualProtect(relay,4096,PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),relay,14))return false;
 const auto displacement=reinterpret_cast<std::intptr_t>(relay)-reinterpret_cast<std::intptr_t>(site+5);
 if(displacement<std::numeric_limits<std::int32_t>::min()||displacement>std::numeric_limits<std::int32_t>::max())return false;
 std::array<unsigned char,5> call{0xe8};auto relative=static_cast<std::int32_t>(displacement);std::memcpy(call.data()+1,&relative,4);
 const std::array<unsigned char,5> expected{0xe8,0x06,0x7f,0x00,0x00};
 return commit(site,call.data(),expected.data(),call.size());
}
}
bool install(HMODULE game,std::string_view list,Logger logger,Commit commit,RejectedSessionCleanup cleanup){
 if(attempted.exchange(true)||!game||!logger||!commit||!cleanup||!policy.load(list))return false;
 audit=logger;
 close_rejected_session=cleanup;
 if(!verify_file(module_path(game),game_hash))return false;
 auto base=reinterpret_cast<unsigned char*>(game);
 auto dos=reinterpret_cast<IMAGE_DOS_HEADER*>(base);
 if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0||dos->e_lfanew>4096)return false;
 auto nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
 if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt->FileHeader.TimeDateStamp!=0x6ad10810||nt->OptionalHeader.SizeOfImage!=0x1dcf000)return false;
 if(std::memcmp(base+registration_rva,registration.data(),registration.size())||
    std::memcmp(base+producer_rva,producer.data(),producer.size())||
    std::memcmp(base+auth_handler_rva,auth_handler.data(),auth_handler.size())||
    std::memcmp(base+dispatch_call_rva,dispatch_call.data(),dispatch_call.size()))return false;
 HMODULE pinned=nullptr;
 if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,reinterpret_cast<LPCWSTR>(filter_queue),&pinned))return false;
 original_queue=reinterpret_cast<Queue>(base+0x9d4fe0);
 if(!install_startup_call(base+0x9cd0d5,reinterpret_cast<void*>(filter_queue),commit))return false;
 char line[160]{};sprintf_s(line,"ESM ADMISSION READY build=25967645 accounts=%zu callback=143 policy_denied=0x45534d01",policy.size());audit(line);
 return true;
}
}
