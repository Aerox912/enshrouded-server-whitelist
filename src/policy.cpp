#include "policy.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>
namespace esm::admission {
bool Policy::load(std::string_view text) {
 ids_.clear();
 if(text.empty()||text.size()>512*19)return false;
 std::vector<std::uint64_t> parsed;
 while(!text.empty()) {
  auto end=text.find('\n');
  auto line=text.substr(0,end);
  if(!line.empty()&&line.back()=='\r')line.remove_suffix(1);
  std::uint64_t id=0;
  auto result=std::from_chars(line.data(),line.data()+line.size(),id);
  if(line.size()!=17||result.ec!=std::errc{}||result.ptr!=line.data()+line.size()||
     (id>>32)!=0x01100001||(id&0xffffffff)==0||
     std::find(parsed.begin(),parsed.end(),id)!=parsed.end()||parsed.size()==512)return false;
  parsed.push_back(id);
  if(end==std::string_view::npos)break;
  text.remove_prefix(end+1);
 }
 std::sort(parsed.begin(),parsed.end());ids_=std::move(parsed);return !ids_.empty();
}
bool Policy::permits(std::uint64_t id) const {return std::binary_search(ids_.begin(),ids_.end(),id);}
bool Policy::filter(Event& event) const {
 if(event[0]!=19)return false;
 std::uint64_t id=0;std::uint32_t response=0;
 std::memcpy(&id,event.data()+8,8);std::memcpy(&response,event.data()+16,4);
 if(response!=0||permits(id))return false;
 std::memcpy(event.data()+16,&policy_denied,4);return true;
}
}
