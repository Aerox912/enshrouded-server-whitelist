#include "policy.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
using namespace esm::admission;
unsigned checks=0;
void check(bool yes,const char* text) { if(!yes){std::printf("FAIL: %s\n",text);std::exit(1);}++checks; }
template<class T>void put(Event& e,size_t at,T v){std::memcpy(e.data()+at,&v,sizeof(v));}
Event auth(std::uint64_t id,std::uint32_t response){Event e{};e.fill(0xa5);e[0]=19;put(e,8,id);put(e,16,response);return e;}
int main(){
 Policy p;
 check(p.load("76561197960265729\r\n76561197960265730\n"),"valid two-account list loads");
 check(p.permits(76561197960265729ull)&&!p.permits(76561197960265731ull),"exact identity membership");
 auto allowed=auth(76561197960265729ull,0),before=allowed;
 check(!p.filter(allowed)&&allowed==before,"successful listed identity preserves whole native event");
 auto denied=auth(76561197960265731ull,0),expected=denied;
 put(expected,16,std::uint32_t{0x45534d01});
 check(p.filter(denied)&&denied==expected,"unlisted success becomes rejection with identity and all other bytes retained");
 for(auto id:{76561197960265729ull,76561197960265731ull}) {
  auto failed=auth(id,7);before=failed;
  check(!p.filter(failed)&&failed==before,"Steam authentication failures never become successes or policy failures");
 }
 auto other=auth(76561197960265731ull,0);other[0]=18;before=other;
 check(!p.filter(other)&&other==before,"unrelated callback untouched");
 for(auto invalid:{"", "\n", "76561197960265729\n76561197960265729\n", "76561197960265729 junk\n", "76561197960265729\n0\n", "12345678\n", "76561197960265728\n", "+76561197960265729\n", "76561197960265729\n\n"}) {
  check(!p.load(invalid)&&p.size()==0&&!p.permits(76561197960265729ull),"invalid reload clears prior permissions and fails closed");
  auto e=auth(76561197960265729ull,0);check(p.filter(e),"empty policy rejects even previously listed identities");
 }
 std::printf("PASS: %u policy checks\n",checks);
}

