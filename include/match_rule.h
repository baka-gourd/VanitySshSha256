#pragma once

#include <re2/re2.h>

#include <string>
#include <string_view>

class MatchRule {
 public:
  explicit MatchRule(std::string pattern);

  bool ok() const;
  bool match(std::string_view text) const;
  const std::string& pattern() const;
  const std::string& error() const;

 private:
  std::string pattern_;
  re2::RE2 re_;
  std::string error_;
};
