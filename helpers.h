#pragma once

#include <mutex>
#include <iostream>

extern std::mutex STDOUT_MX;
extern std::mutex STDERR_MX;

#define STDERR(x) do { STDERR_MX.lock();std::cerr << __func__ << ":" <<__LINE__ << ": " << x << std::endl; STDERR_MX.unlock(); } while (0)
#define STDOUT(x) do { STDERR_MX.lock();std::cout << x << std::endl; STDERR_MX.unlock(); } while (0)
