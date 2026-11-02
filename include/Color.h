#ifndef COLOR_H
#define COLOR_H

#include <iostream>

namespace Color {
    static const char* const RESET   = "\033[0m";
    static const char* const BOLD    = "\033[1m";
    static const char* const RED     = "\033[91m";
    static const char* const GREEN   = "\033[92m";
    static const char* const YELLOW  = "\033[93m";
    static const char* const BLUE    = "\033[94m";
    static const char* const MAGENTA = "\033[95m";
    static const char* const CYAN    = "\033[96m";
    static const char* const WHITE   = "\033[97m";
    static const char* const BG_BLUE = "\033[44m";
}

#endif // COLOR_H
