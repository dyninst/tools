cmake_minimum_required(VERSION 2.8.4)
project(current)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

find_package(BISON)
find_package(FLEX)

BISON_TARGET(bison_out parser.yy ${CMAKE_CURRENT_BINARY_DIR}/y.tab.cc COMPILE_FLAGS -dy)
FLEX_TARGET(flex_out scanner.ll  ${CMAKE_CURRENT_BINARY_DIR}/lex.yy.cc)
#ADD_FLEX_BISON_DEPENDENCY(flex_out bison_out)

include_directories(${CMAKE_CURRENT_BINARY_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR})
add_executable(current
        ${CMAKE_CURRENT_SOURCE_DIR}/driver.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/main.cc
        ${BISON_bison_out_OUTPUTS}
        ${FLEX_flex_out_OUTPUTS})

#target_link_libraries(current ${FLEX_LIBRARIES} ${BISON_LIBRARIES})
