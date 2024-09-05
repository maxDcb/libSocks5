cmake_minimum_required(VERSION 3.5)
project(SocksServer VERSION 1.0.0 LANGUAGES CXX)

set(DEFAULT_BUILD_TYPE "Release")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    set(SOURCE_FILES
    src/SocksTunnelClient.cpp
    )
else()
    set(SOURCE_FILES
    src/SocksServer.cpp
    src/SocksTunnelClient.cpp
    )
endif()

include_directories(../src)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
set_property(TARGET ${PROJECT_NAME} PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_include_directories(${PROJECT_NAME} PUBLIC src)
set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

if(WIN32)
else()
    add_subdirectory(tests)
endif()