cmake_minimum_required(VERSION 3.14)
project(OnPremiseSecurityDemo)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pipe -fvisibility=hidden")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now -Wl,-z,noexecstack")

find_package(nlohmann_json 3.11 REQUIRED)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED gtk4)
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-mu tss2-rc tss2-tctildr)

# Installer (CLI)
add_executable(secure_installer
  src/main.cpp
  src/fingerprint.cpp
  src/verifier.cpp
  src/app_loader.cpp
  src/anti_re.cpp
  src/license_embed.cpp
  src/tpm_attest.cpp
  src/tpm_seal.cpp
  src/secure_logger.cpp
)
target_include_directories(secure_installer PRIVATE include)
target_link_libraries(secure_installer PRIVATE
  OpenSSL::SSL OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  dl Threads::Threads
  ${TSS2_LIBRARIES}
)

# GUI Installer
add_executable(secure_installer_gui
  src/gui_installer.cpp
  src/fingerprint.cpp
  src/verifier.cpp
  src/app_loader.cpp
  src/anti_re.cpp
  src/license_embed.cpp
  src/tpm_attest.cpp
  src/tpm_seal.cpp
  src/secure_logger.cpp
)
target_include_directories(secure_installer_gui PRIVATE include ${GTK4_INCLUDE_DIRS} ${TSS2_INCLUDE_DIRS})
target_link_libraries(secure_installer_gui PRIVATE
  OpenSSL::SSL OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  dl Threads::Threads
  ${GTK4_LIBRARIES}
  ${TSS2_LIBRARIES}
)
target_compile_options(secure_installer_gui PRIVATE ${GTK4_CFLAGS_OTHER})

# Protected core application (shared library)
add_library(secure_app_core SHARED
  src/app_core.cpp
  src/anti_re.cpp
  src/license_embed.cpp
  src/verifier.cpp
  src/secure_logger.cpp
  src/fingerprint.cpp
  src/tpm_attest.cpp
  src/license_api.cpp
)
target_include_directories(secure_app_core PRIVATE include ${TSS2_INCLUDE_DIRS})
target_link_libraries(secure_app_core PRIVATE
  OpenSSL::SSL OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  Threads::Threads
  dl
  ${TSS2_LIBRARIES}
)

# Vendor tools
add_executable(keygen tools/keygen.cpp)
target_link_libraries(keygen PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(sign_license tools/sign_license.cpp)
target_link_libraries(sign_license PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)

add_executable(encrypt_core tools/encrypt_core.cpp)
target_link_libraries(encrypt_core PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(audit_decrypt tools/audit_decrypt.cpp)
target_link_libraries(audit_decrypt PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(get_fingerprint
  tools/get_fingerprint.cpp
  src/fingerprint.cpp
  src/tpm_attest.cpp
)
target_include_directories(get_fingerprint PRIVATE include ${TSS2_INCLUDE_DIRS})
target_link_libraries(get_fingerprint PRIVATE
  OpenSSL::SSL OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  ${TSS2_LIBRARIES}
)