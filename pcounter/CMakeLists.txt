add_executable(pcounter main.c)
target_include_directories(pcounter PRIVATE
    ${PCAP_INCLUDE_DIRS}
    ${POPT_INCLUDE_DIRS}
)
target_link_libraries(pcounter PRIVATE
    m
    ${PCAP_LIBRARIES}
    ${POPT_LIBRARIES}
)
install(TARGETS pcounter RUNTIME DESTINATION bin)
