#pragma once
#include <string>

// Returns a stable hardware identifier string (SHA-256 hex over machine info)
std::string GetHWID();
