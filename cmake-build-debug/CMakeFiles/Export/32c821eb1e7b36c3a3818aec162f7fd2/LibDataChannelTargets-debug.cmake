#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "LibDataChannel::LibDataChannel" for configuration "Debug"
set_property(TARGET LibDataChannel::LibDataChannel APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(LibDataChannel::LibDataChannel PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libdatachannel.0.dylib"
  IMPORTED_SONAME_DEBUG "@rpath/libdatachannel.0.dylib"
  )

list(APPEND _cmake_import_check_targets LibDataChannel::LibDataChannel )
list(APPEND _cmake_import_check_files_for_LibDataChannel::LibDataChannel "${_IMPORT_PREFIX}/lib/libdatachannel.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
