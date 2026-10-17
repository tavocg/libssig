add_executable(noop_test noop.test.c)
target_link_libraries(noop_test PRIVATE libssig::ssig)
target_compile_options(noop_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME noop COMMAND noop_test)
