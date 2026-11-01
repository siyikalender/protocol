# Tests of the protocol library
#
# This is free and unencumbered software released into the public domain.
# For more information, please refer to <http://unlicense.org> and the
# LICENSE file in the root of this repository.
#
# Author: Claude Opus 5.5 <noreply@anthropic.com>
# Date:   2026

add_executable(protocol_test_pool test_pool.cpp)
target_link_libraries(protocol_test_pool PRIVATE protocol::ipv4 protocol_warnings)
add_test(NAME pool COMMAND protocol_test_pool)

add_executable(protocol_test_grammar test_grammar.cpp)
target_link_libraries(protocol_test_grammar PRIVATE protocol::ipv4 protocol_warnings)
add_test(NAME grammar COMMAND protocol_test_grammar)

# The stack state is global: every case runs in its own process
function(protocol_cases executable source)
  add_executable(${executable} ${source})
  target_link_libraries(${executable} PRIVATE protocol::ipv4 protocol_warnings)
  foreach(name ${ARGN})
    add_test(NAME ${name} COMMAND ${executable} ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 30)
  endforeach()
endfunction()

protocol_cases(protocol_test_behaviour test_behaviour.cpp
  arp_reply_to_many_hosts
  udp_receive_mixed_sizes
  udp_receive_queued_in_order
  udp_lying_total_length_dropped
  udp_bad_ip_checksum_dropped
  udp_with_tos_delivered
  udp_send_once_with_valid_checksums
  icmp_echo_small_padded
  icmp_echo_large)

protocol_cases(protocol_test_api test_api.cpp
  zero_copy_echo
  allocate_and_drop
  reserves_keep_both_directions_alive
  arp_retry_then_timeout
  arp_retry_without_clock
  arp_answer_after_retry
  broadcast
  bind_rules
  short_frames_padded
  no_leaks)

protocol_cases(protocol_test_dma test_dma.cpp
  dma_arp_and_ping
  dma_zero_copy_echo
  dma_echo_with_ip_options
  dma_tx_ring_full
  dma_replies_while_tx_stuck
  dma_overload_cut_at_ring
  dma_arp_timeout)

# The example runs as a test too, so it keeps compiling
add_executable(protocol_example ${PROJECT_SOURCE_DIR}/examples/test/main.cpp)
target_link_libraries(protocol_example PRIVATE protocol::ipv4)
target_compile_definitions(protocol_example PRIVATE DEBUG)
add_test(NAME example COMMAND protocol_example)
