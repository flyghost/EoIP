# # 查找测试框架
# find_package(CUnit REQUIRED)

# # 添加测试可执行文件
# add_executable(tftp_stack_tests
#     # 这里添加你的测试源文件
#     # test_tftp_stack.c
# )

# target_link_libraries(tftp_stack_tests
#     tftp_stack
#     CUnit::CUnit
# )

# # 添加测试用例
# add_test(NAME tftp_stack_test
#     COMMAND tftp_stack_tests
# )

# # 安装测试程序(可选)
# install(TARGETS tftp_stack_tests
#     RUNTIME DESTINATION bin
# )