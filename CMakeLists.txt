CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

PROJECT(shadow
    VERSION 1.0
    DESCRIPTION "mTLS reverse tunnel similar to 'ssh -R'"
)

IF(NOT EXISTS ${CMAKE_BINARY_DIR}/CMakeCache.txt)
  IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
  ENDIF()
ENDIF()

# Turn all warnings
STRING(APPEND CMAKE_CXX_FLAGS " -Wall -Wextra -Werror")

ADD_EXECUTABLE(shadow-server
    src/shadow-server.cc
)

ADD_EXECUTABLE(shadow-client
    src/shadow-client.cc
)

SET(OPENSSL_USE_STATIC_LIBS TRUE)
FIND_PACKAGE(OpenSSL REQUIRED)

IF(OPENSSL_VERSION VERSION_LESS "3.0.0")
  MESSAGE(
    FATAL_ERROR
    "OpenSSL >= 3.0.0 is required for ktls support. "
    "If you have OpenSSL installed somewhere outside system directories, "
    "try the following command: "
    "'cmake $shadow_dir -DOPENSSL_ROOT_DIR=$openssl_install_dir'"
  )
ENDIF()

TARGET_LINK_LIBRARIES(shadow-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(shadow-client PRIVATE OpenSSL::SSL OpenSSL::Crypto)

INSTALL(
    TARGETS shadow-server shadow-client
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

MESSAGE(STATUS "CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")
MESSAGE(STATUS "CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "###### DON'T FORGET TO RUN 'modprobe tls' ON YOUR SYSTEM ! ######")