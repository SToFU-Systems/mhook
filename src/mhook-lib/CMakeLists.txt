project(mhook-lib LANGUAGES C)

set(MHOOK_INCLUDES
    include/mhook-lib/mhook.h
)

set(MHOOK_SOURCES
    src/mhook.c
)

source_group("include/mhook-lib" FILES ${MHOOK_INCLUDES})
source_group("src" FILES ${MHOOK_SOURCES})

add_library(mhook_headers INTERFACE)
add_library(mhook::headers ALIAS mhook_headers)
set_target_properties(mhook_headers PROPERTIES EXPORT_NAME headers)
target_include_directories(mhook_headers INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${MHOOK_GENERATED_INCLUDE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_sources(mhook_headers INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/mhook-lib/mhook.h>"
)

add_library(mhook STATIC ${MHOOK_SOURCES} ${MHOOK_INCLUDES} $<TARGET_OBJECTS:mhook_disasm>)
add_library(mhook::mhook ALIAS mhook)
target_link_libraries(mhook PUBLIC mhook_headers)
# The decoder's objects are already embedded through $<TARGET_OBJECTS:> above,
# so the only thing a link would add is its include directory. Taking that
# directly keeps mhook_disasm out of INTERFACE_LINK_LIBRARIES entirely, rather
# than linking it and then hiding it behind a generator expression that leaves
# an empty $<LINK_ONLY:> entry in the exported package.
target_include_directories(mhook PRIVATE
    "$<TARGET_PROPERTY:mhook_disasm,INTERFACE_INCLUDE_DIRECTORIES>"
)
target_compile_features(mhook PRIVATE c_std_99)
set_target_properties(mhook PROPERTIES C_EXTENSIONS ON)

# mhook.c includes its own header as "mhook.h".
target_include_directories(mhook PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include/mhook-lib"
)

mhook_configure_private_target(mhook)
