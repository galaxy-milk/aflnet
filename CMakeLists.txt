# Date:   Mon Feb 17 03:42:08 PM 2025
# Mail:   lunar_ubuntu@qq.com
# Author: https://github.com/xiaoqixian

cmake_minimum_required(VERSION 3.10)
project(AFL VERSION 1.0)

# 设置默认的安装路径
set(PREFIX /usr/local)
set(BIN_PATH ${PREFIX}/bin)
set(HELPER_PATH ${PREFIX}/lib/afl)
set(DOC_PATH ${PREFIX}/share/doc/afl)
set(MISC_PATH ${PREFIX}/share/afl)

# 编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAFL_PATH=\"${HELPER_PATH}\" -DDOC_PATH=\"${DOC_PATH}\" -DBIN_PATH=\"${BIN_PATH}\"")

# 判断操作系统类型（Linux）
if(UNIX AND NOT APPLE)
    set(LDFLAGS "${LDFLAGS} -ldl -lgvc -lcgraph -lm -lcap")
endif()

# 设置编译器
if(NOT CMAKE_CXX_COMPILER_VERSION MATCHES "clang")
    set(TEST_CC "afl-gcc")
else()
    set(TEST_CC "afl-clang")
endif()

# 设置目标文件列表
set(COMM_HDR alloc-inl.h config.h debug.h types.h)
set(PROGS afl-gcc afl-fuzz afl-replay aflnet-replay afl-showmap afl-tmin afl-gotcpu afl-analyze)
set(SH_PROGS afl-plot afl-cmin afl-whatsup)

# 添加执行目标
add_executable(afl-gcc afl-gcc.c ${COMM_HDR})
target_compile_options(afl-gcc PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-gcc ${LDFLAGS})

add_executable(afl-fuzz afl-fuzz.c ${COMM_HDR} aflnet.o aflnet.h)
target_compile_options(afl-fuzz PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-fuzz ${LDFLAGS})

add_executable(afl-replay afl-replay.c ${COMM_HDR} aflnet.o aflnet.h)
target_compile_options(afl-replay PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-replay ${LDFLAGS})

add_executable(aflnet-replay aflnet-replay.c ${COMM_HDR} aflnet.o aflnet.h)
target_compile_options(aflnet-replay PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(aflnet-replay ${LDFLAGS})

add_executable(afl-showmap afl-showmap.c ${COMM_HDR})
target_compile_options(afl-showmap PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-showmap ${LDFLAGS})

add_executable(afl-tmin afl-tmin.c ${COMM_HDR})
target_compile_options(afl-tmin PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-tmin ${LDFLAGS})

add_executable(afl-analyze afl-analyze.c ${COMM_HDR})
target_compile_options(afl-analyze PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-analyze ${LDFLAGS})

add_executable(afl-gotcpu afl-gotcpu.c ${COMM_HDR})
target_compile_options(afl-gotcpu PRIVATE ${CMAKE_C_FLAGS})
target_link_libraries(afl-gotcpu ${LDFLAGS})

# 安装文件
install(TARGETS ${PROGS} ${SH_PROGS} RUNTIME DESTINATION ${BIN_PATH})

# 创建符号链接
foreach(PROG IN LISTS PROGS)
    execute_process(COMMAND ln -sf ${PROG} ${BIN_PATH}/${PROG})
endforeach()

# 设置安装路径
install(DIRECTORY docs/ DESTINATION ${DOC_PATH})
install(DIRECTORY testcases/ DESTINATION ${MISC_PATH})
install(DIRECTORY dictionaries/ DESTINATION ${MISC_PATH})

# 清理目标
add_custom_target(clean
    COMMAND rm -f ${PROGS} afl-as as afl-g++ afl-clang afl-clang++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test test-instr .test-instr0 .test-instr1
    COMMAND rm -rf out_dir qemu_mode/qemu-2.10.0
    COMMAND ${CMAKE_COMMAND} --build . --target clean
)

# 安装并创建符号链接
add_custom_target(install
    COMMAND mkdir -p ${DESTDIR}${BIN_PATH} ${DESTDIR}${HELPER_PATH} ${DESTDIR}${DOC_PATH} ${DESTDIR}${MISC_PATH}
    COMMAND install -m 755 ${PROGS} ${SH_PROGS} ${DESTDIR}${BIN_PATH}
    COMMAND ln -sf afl-gcc ${DESTDIR}${BIN_PATH}/afl-g++
    COMMAND ln -sf afl-gcc ${DESTDIR}${BIN_PATH}/afl-clang++
    COMMAND install -m 755 afl-as ${DESTDIR}${HELPER_PATH}
    COMMAND ln -sf afl-as ${DESTDIR}${HELPER_PATH}/as
    COMMAND install -m 644 docs/README docs/ChangeLog docs/*.txt ${DESTDIR}${DOC_PATH}
    COMMAND cp -r testcases/ ${DESTDIR}${MISC_PATH}
    COMMAND cp -r dictionaries/ ${DESTDIR}${MISC_PATH}
)

# 发布目标
add_custom_target(publish
    COMMAND cd .. && rm -rf ${PROGNAME}-${VERSION}
    COMMAND cp -pr ${PROGNAME} ${PROGNAME}-${VERSION}
    COMMAND tar -cvz -f ~/www/afl/releases/${PROGNAME}-${VERSION}.tgz ${PROGNAME}-${VERSION}
    COMMAND chmod 644 ~/www/afl/releases/${PROGNAME}-${VERSION}.tgz
    COMMAND ln -s -f ${PROGNAME}-${VERSION}.tgz ~/www/afl/releases/${PROGNAME}-latest.tgz
)
