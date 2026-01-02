# FindLibMemKit.cmake - CMake module to locate libmemkit library
find_path(libmemkit_INCLUDE_DIR memkit.h
    PATHS /usr/local/include /usr/include ${CMAKE_INSTALL_PREFIX}/include
)

find_library(libmemkit_LIBRARY MemoryManager
    PATHS /usr/local/lib /usr/lib ${CMAKE_INSTALL_PREFIX}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libmemkit DEFAULT_MSG
    libmemkit_LIBRARY libmemkit_INCLUDE_DIR
)

if(MemoryManager_FOUND AND NOT TARGET libmemkit::libmemkit)
    add_library(libmemkit::libmemkit UNKNOWN IMPORTED)
    set_target_properties(libmemkit::libmemkit PROPERTIES
        IMPORTED_LOCATION "${libmemkit_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${libmemkit_INCLUDE_DIR}"
    )
    
    # Link pthreads if available (MemoryManager might need it)
    find_package(Threads QUIET)
    if(Threads_FOUND)
        set_target_properties(libmemkit::libmemkit PROPERTIES
            INTERFACE_LINK_LIBRARIES "Threads::Threads"
        )
    endif()
endif()
