cmake_minimum_required(VERSION 3.16)
project(clawguard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(clawguard
    main.cpp
    util.cpp
    config.cpp
    collector.cpp
    alerts.cpp
    http_server.cpp
    dashboard.cpp
)

target_link_libraries(clawguard PRIVATE pthread)

# Optimize for release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(clawguard PRIVATE -O2 -DNDEBUG)
endif()

install(TARGETS clawguard DESTINATION bin)
