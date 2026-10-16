#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>
namespace esm::admission {
// Exact native backend queue record; constructed from Steam callback 143.
using Event = std::array<unsigned char, 0x2d0>;
inline constexpr std::uint32_t policy_denied = 0x45534d01;
class Policy {
 public:
  bool load(std::string_view text);
  bool permits(std::uint64_t id) const;
  bool filter(Event& event) const;
  std::size_t size() const { return ids_.size(); }
 private:
  std::vector<std::uint64_t> ids_;
};
}
