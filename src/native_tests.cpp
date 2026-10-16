#include "runtime.hpp"
#include "policy.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
using namespace esm::admission;
unsigned checks=0,calls=0,cleanups=0;Event captured{};void* expected_queue=nullptr;
bool cleanup_ok=true;
void check(bool ok,const char* message){if(!ok){std::printf("FAIL: %s\n",message);std::exit(1);}++checks;}
void write(void* where,const void* data,size_t n){DWORD old=0,ignored=0;check(VirtualProtect(where,n,PAGE_EXECUTE_READWRITE,&old)!=0,"test protect");std::memcpy(where,data,n);check(VirtualProtect(where,n,old,&ignored)&&FlushInstructionCache(GetCurrentProcess(),where,n),"test protection restore");}
void jump(void* where,void* target){std::array<unsigned char,14> code{0xff,0x25};std::memcpy(code.data()+6,&target,8);write(where,code.data(),code.size());}
bool lock(void* q){check(q==expected_queue,"native queue receives same backend context");++calls;return true;}
std::uint64_t ticks(){return 100;}
void* zero(void* p,int c,size_t n){return std::memset(p,c,n);}
void log(const char* s){std::puts(s);}
bool cleanup(std::uint64_t id){check(id==76561197960265731ULL,"only denied authenticated account is cleaned up");++cleanups;return cleanup_ok;}
bool commit(void* site,const void* replacement,const void* expected,size_t n){check(!std::memcmp(site,expected,n),"commit preimage matches");write(site,replacement,n);return !std::memcmp(site,replacement,n);}
int wmain(int argc,wchar_t** argv){
 check(argc>=2,"fixture argument");auto game=LoadLibraryExW(argv[1],nullptr,DONT_RESOLVE_DLL_REFERENCES);check(game!=nullptr,"inert dedicated PE mapping");auto base=reinterpret_cast<unsigned char*>(game);
 const bool tamper=argc==3&&std::wstring(argv[2])==L"tamper";
 const bool invalid=argc==3&&std::wstring(argv[2])==L"invalid";
 const bool no_cleanup=argc==3&&std::wstring(argv[2])==L"no-cleanup";
 if(tamper){unsigned char nop=0x90;write(base+0x9cd0d5,&nop,1);}
 const auto ok=install(game,invalid?"": "76561197960265729\n",log,commit,no_cleanup?nullptr:cleanup);
 if(tamper||invalid||no_cleanup){check(!ok,"invalid native code, policy or absent cleanup refuses installation");std::printf("PASS: %u rejection checks\n",checks);return 0;}
 check(ok,"guard installs on exact dedicated hotfix");
 // Execute the actual producer, guard, and native queue. Stub only OS clock,
 // lock acquisition and the zero-fill boundary in the inert mapped image.
 jump(base+0x556700,reinterpret_cast<void*>(ticks));jump(base+0x572460,reinterpret_cast<void*>(lock));jump(base+0xbc3ae0,reinterpret_cast<void*>(zero));
 using Producer=void(*)(void*,void*);auto producer=reinterpret_cast<Producer>(base+0x9cd070);
 std::array<unsigned char,256> backend{};std::array<Event,2> slots{};expected_queue=backend.data()+0x58;
 auto q=static_cast<unsigned char*>(expected_queue);
 auto set=[&](size_t offset,std::uint64_t value){std::memcpy(q+offset,&value,8);};
 set(0x10,reinterpret_cast<std::uint64_t>(slots.data()));set(0x18,2);
 std::uint64_t index=0;
 struct Raw{std::uint64_t id;std::uint32_t response,pad;std::uint64_t owner;};
 for(const auto r:{Raw{76561197960265729ULL,0,0,42},Raw{76561197960265731ULL,0,0,43},Raw{76561197960265729ULL,7,0,44}}){
  auto raw=r;set(0x20,index);set(0x28,index);producer(backend.data(),&raw);captured=slots[index%2];++index;std::uint64_t id=0;std::uint32_t response=0;
  std::memcpy(&id,captured.data()+8,8);std::memcpy(&response,captured.data()+16,4);
  check(captured[0]==19&&id==r.id,"actual native producer preserves callback identity/type");
  check(response==(r.id==76561197960265731ULL?0x45534d01u:r.response),"native callback path permits owner, denies absent account, preserves Steam failure");
  check(!std::memcmp(&raw,&r,sizeof(raw)),"original Steam callback payload not mutated");
  check(cleanups==(index>=2?1u:0u),"one Steam auth cleanup for denial and none for allowed or genuine Steam failure");
  std::memset(&raw,0,sizeof(raw));check(slots[(index-1)%2]==captured,"native queue owns full copy after callback input changes");
 }
 check(calls==3,"one queued event per callback");
 cleanup_ok=false;
 Raw rejected{76561197960265731ULL,0,0,43};set(0x20,index);set(0x28,index);producer(backend.data(),&rejected);
 std::uint32_t denied_response=0;std::memcpy(&denied_response,slots[index%2].data()+16,4);
 check(denied_response==0x45534d01u&&cleanups==2,"cleanup failure cannot allow an unlisted account");
 set(0x20,2);set(0x28,0);auto before=slots;
 using NativeQueue=bool(*)(void*,const Event*,std::uint64_t);
 check(!reinterpret_cast<NativeQueue>(base+0x9d4fe0)(q,&captured,0)&&slots==before,"full queue reports false at expired deadline without storing input");
 std::printf("PASS: %u exact-native producer/guard checks\n",checks);
}
