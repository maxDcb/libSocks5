add_executable(TestsSocksServer "TestsSocksServer.cpp" )
set_property(TARGET TestsSocksServer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(TestsSocksServer SocksServer )

