add_executable(TestsSocksServer "TestsSocksServer.cpp" )
set_property(TARGET TestsSocksServer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
	target_link_libraries(TestsSocksServer SocksServer)
else()
	target_link_libraries(TestsSocksServer SocksServer pthread)
endif()