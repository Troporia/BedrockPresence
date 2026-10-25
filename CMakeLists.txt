cmake_minimum_required(VERSION 4.3)
project(BedrockPresence LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT so the payload does not depend on whatever runtime DLLs the game ships.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
# Some dependencies still declare an old cmake_minimum_required.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

include(FetchContent)

FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG v1.3.4
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(minhook)

FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(INSTALL_PROJECT OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    miniz
    GIT_REPOSITORY https://github.com/richgel999/miniz.git
    GIT_TAG 3.0.2
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(miniz)

add_library(bedrock_presence SHARED
    src/payload/dllmain.cpp
    src/payload/logging.cpp
    src/payload/config.cpp
    src/payload/sigscan.cpp
    src/payload/dns_cache.cpp
    src/payload/session.cpp
    src/payload/raknet.cpp
    src/payload/nethernet.cpp
    src/payload/net_hook.cpp
    src/payload/packet_send.cpp
    src/payload/discord_ipc.cpp
    src/payload/tls.cpp
    src/payload/link.cpp)
target_link_libraries(bedrock_presence PRIVATE
    minhook
    nlohmann_json::nlohmann_json
    miniz
    ws2_32 secur32 crypt32 bcrypt psapi user32)
target_include_directories(bedrock_presence PRIVATE ${minhook_SOURCE_DIR}/include)
target_compile_definitions(bedrock_presence PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

add_executable(bedrock_presence_injector src/injector/main.cpp)
target_link_libraries(bedrock_presence_injector PRIVATE advapi32)
