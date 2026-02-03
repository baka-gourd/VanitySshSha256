#include "match_rule.h"

#include <utility>

MatchRule::MatchRule(std::string pattern)
    : pattern_(std::move(pattern)), re_(pattern_) {
  if (!re_.ok()) {
    error_ = re_.error();
  }
}

bool MatchRule::ok() const {
  return re_.ok();
}

bool MatchRule::match(std::string_view text) const {
  return re2::RE2::PartialMatch(re2::StringPiece(text.data(), text.size()), re_);
}

const std::string& MatchRule::pattern() const {
  return pattern_;
}

const std::string& MatchRule::error() const {
  return error_;
}
