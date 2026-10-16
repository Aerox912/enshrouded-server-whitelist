#pragma once
#include <windows.h>
#include <string_view>
#include <cstdint>
namespace esm::admission {
using Logger=void(*)(const char*);
using Commit=bool(*)(void* site,const void* replacement,const void* expected,std::size_t size);
using RejectedSessionCleanup=bool(*)(std::uint64_t steam_id);
bool install(HMODULE game,std::string_view list,Logger logger,Commit commit,RejectedSessionCleanup cleanup);
}
