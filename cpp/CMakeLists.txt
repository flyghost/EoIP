cmake_minimum_required(VERSION 3.10)
project(TftpProtocolStack VERSION 1.0 LANGUAGES C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 配置编译选项
option(BUILD_TESTING "Build unit tests" OFF)
option(BUILD_CLIENT "Build TCP client example" ON)

# 添加库目标
add_library(tftp_stack STATIC 
    src/tftp_stack.c
)

# 包含目录
target_include_directories(tftp_stack PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 客户端可执行文件
if(BUILD_CLIENT)
    add_executable(tftp_client 
        src/tftp_tcp_client.c
    )
    
    target_link_libraries(tftp_client 
        tftp_stack
    )
    
    # Linux下需要链接socket库
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(tftp_client 
            pthread
        )
    endif()
endif()

# 启用测试
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

# 安装规则
install(TARGETS tftp_stack
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

install(DIRECTORY include/ 
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)