#ifndef DEFS_HPP
#define DEFS_HPP

#ifndef DEBUG

#define TRACE(P)

#else

#include <iostream>
#define TRACE(P) std::cout<<P

// DEBUG
#endif

// DEFS_HPP
#endif 
