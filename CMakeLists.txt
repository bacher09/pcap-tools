cmake_minimum_required(VERSION 3.6)
# networking troubleshooting tools
project(nt-tools LANGUAGES C)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(PCAP REQUIRED)
find_package(POPT REQUIRED)
# subprojects
add_subdirectory("${PROJECT_SOURCE_DIR}/pcounter/")

option(CPACK_PACKAGING "Build package with CPACK" OFF)

if(CPACK_PACKAGING)
    string(TIMESTAMP PACKAGE_DATE "%Y-%m-%d" UTC)
    set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
    set(CPACK_PACKAGE_VERSION_MAJOR "0")
    set(CPACK_PACKAGE_VERSION_MINOR "1")
    set(CPACK_PACKAGE_VERSION_PATCH "1")
    set(CPACK_PACKAGE_VERSION
        "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}"
    )
    set(CPACK_PACKAGE_FILE_NAME
        "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${PACKAGE_DATE}"
    )
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Slava Bacherikov")
    set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "networking-troubleshooting-tools")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libc6, pcap, popt"
    )
    set(CPACK_GENERATOR "TGZ" "ZIP" "DEB" "RPM")
    include(CPack)
endif()
