cmake_minimum_required(VERSION 3.5)
project(SocksServer VERSION 1.0.0 LANGUAGES CXX)

set(DEFAULT_BUILD_TYPE "Release")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_FILES
src/SocksServer.cpp
src/SocksTunnelClient.cpp
)

include_directories(../src)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
set_property(TARGET ${PROJECT_NAME} PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_include_directories(${PROJECT_NAME} PUBLIC src)
set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

if(WIN32)
else()
	target_link_libraries(${PROJECT_NAME} pthread)
endif()

add_subdirectory(tests)
