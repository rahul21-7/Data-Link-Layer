#ifndef COLOR_H
#define COLOR_H

#include <iostream>

namespace Color {
    inline const char* RESET   = "\033[0m";
    inline const char* BOLD    = "\033[1m";
    inline const char* RED     = "\033[91m";
    inline const char* GREEN   = "\033[92m";
    inline const char* YELLOW  = "\033[93m";
    inline const char* BLUE    = "\033[94m";
    inline const char* MAGENTA = "\033[95m";
    inline const char* CYAN    = "\033[96m";
    inline const char* WHITE   = "\033[97m";
    inline const char* BG_BLUE = "\033[44m";
}

#endif // COLOR_H

