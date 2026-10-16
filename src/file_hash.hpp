#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <string>
#include <cstring>
namespace esm::admission {
inline constexpr char game_hash[]="4de2acdd3b18e562f129bc488a2daea2da16b00341497304423e1e18c49a83ba";
inline std::wstring module_path(HMODULE module){
 std::wstring p(32768,L'\0');auto n=GetModuleFileNameW(module,p.data(),static_cast<DWORD>(p.size()));
 if(!n||n>=p.size())return {};p.resize(n);return p;
}
inline bool verify_file(const std::wstring& path,const char* expected){
 HANDLE file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
 if(file==INVALID_HANDLE_VALUE)return false;
 BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
 bool ok=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0;
 if(ok)ok=BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0)>=0;
 std::array<unsigned char,65536> buffer{};DWORD n=0;
 while(ok){if(!ReadFile(file,buffer.data(),static_cast<DWORD>(buffer.size()),&n,nullptr)){ok=false;break;}if(!n)break;ok=BCryptHashData(hash,buffer.data(),n,0)>=0;}
 std::array<unsigned char,32> digest{};if(ok)ok=BCryptFinishHash(hash,digest.data(),32,0)>=0;
 if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);CloseHandle(file);
 char hex[65]{};constexpr char digits[]="0123456789abcdef";
 for(size_t i=0;i<32;++i){hex[2*i]=digits[digest[i]>>4];hex[2*i+1]=digits[digest[i]&15];}
 return ok&&std::strcmp(hex,expected)==0;
}
}
