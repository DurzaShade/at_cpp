cmake_minimum_required(VERSION 3.22)
project(openssltest)

set(CMAKE_CXX_STANDARD 14)

add_executable(openssltest main.cpp)

set(OPENSSL_ROOT_DIR  "C:\\Program Files\\OpenSSL-Win64")
find_package(OpenSSL REQUIRED)

include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.10.5/json.tar.xz)
FetchContent_MakeAvailable(json)


target_link_libraries(openssltest PRIVATE OpenSSL::SSL)
target_include_directories(openssltest PRIVATE "C:\\Program Files\\OpenSSL-Win64\\include")
target_link_directories(openssltest PRIVATE "C:\\Program Files\\OpenSSL-Win64\\lib")
target_link_libraries(openssltest PRIVATE ssl crypto)
target_link_libraries(openssltest PRIVATE nlohmann_json::nlohmann_json)

