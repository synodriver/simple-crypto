cmake_minimum_required(VERSION 2.6)
project(simple-crypto C)

#add_compile_definitions(TEA_NORAND)
#SET(CMAKE_BUILD_TYPE "Release")
# change this to your lua.h directory
include_directories(D:\\conda\\envs\\py310\\Library\\include .)
# change this to your lua.lib\liblua.a directory
link_directories("D:\\conda\\envs\\py310\\Library\\lib" D:\\conda\\envs\\py310\\Library\\bin)

include(TestBigEndian)
test_big_endian(isBigEndian)
if (${isBigEndian})
    MESSAGE("isBigEndian")
    add_definitions(-DWORDS_BIGENDIAN)
else()
    MESSAGE("issmallEndian")
endif()

set(TEST 0)
if(TEST)
    add_definitions(-DTEST_SIMPLE_CRYPTO)
    add_executable(smd5 md5.c)
    add_executable(stea tea.c)
else()
    add_library(scrypto SHARED md5.c tea.c)
    INSTALL(TARGETS scrypto LIBRARY DESTINATION lib)
    INSTALL(FILES simplecrypto.h DESTINATION include)
endif()

add_library(tea SHARED tea.c src/ltea.c)
target_link_libraries(tea lua)
set_target_properties(tea PROPERTIES OUTPUT_NAME tea PREFIX "")