# Install script for directory: /Users/shaw/Code/libdatachannel

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Library/Developer/CommandLineTools/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/shaw/Code/libdatachannel/cmake-build-debug/libdatachannel.0.dylib")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.0.dylib" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.0.dylib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -x "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libdatachannel.0.dylib")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/shaw/Code/libdatachannel/cmake-build-debug/libdatachannel.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/rtc" TYPE FILE FILES
    "/Users/shaw/Code/libdatachannel/include/rtc/candidate.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/channel.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/configuration.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/datachannel.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/description.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/mediahandler.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtcpreceivingsession.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/common.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/global.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/message.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/frameinfo.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/peerconnection.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/reliability.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtc.h"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtc.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtp.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/track.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/websocket.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/websocketserver.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtppacketizationconfig.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtcpsrreporter.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtppacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtpdepacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/h264rtppacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/h264rtpdepacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/nalunit.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/h265rtppacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/h265rtpdepacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/h265nalunit.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/av1rtppacketizer.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rtcpnackresponder.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/utils.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/plihandler.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/pacinghandler.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/rembhandler.hpp"
    "/Users/shaw/Code/libdatachannel/include/rtc/version.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets.cmake"
         "/Users/shaw/Code/libdatachannel/cmake-build-debug/CMakeFiles/Export/32c821eb1e7b36c3a3818aec162f7fd2/LibDataChannelTargets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel/LibDataChannelTargets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel" TYPE FILE FILES "/Users/shaw/Code/libdatachannel/cmake-build-debug/CMakeFiles/Export/32c821eb1e7b36c3a3818aec162f7fd2/LibDataChannelTargets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel" TYPE FILE FILES "/Users/shaw/Code/libdatachannel/cmake-build-debug/CMakeFiles/Export/32c821eb1e7b36c3a3818aec162f7fd2/LibDataChannelTargets-debug.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/LibDataChannel" TYPE FILE FILES
    "/Users/shaw/Code/libdatachannel/cmake-build-debug/LibDataChannelConfig.cmake"
    "/Users/shaw/Code/libdatachannel/cmake-build-debug/LibDataChannelConfigVersion.cmake"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/client/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/client-benchmark/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/media-receiver/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/media-sender/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/media-sfu/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/streamer/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/copy-paste/cmake_install.cmake")
  include("/Users/shaw/Code/libdatachannel/cmake-build-debug/examples/copy-paste-capi/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/shaw/Code/libdatachannel/cmake-build-debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
