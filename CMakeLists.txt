cmake_minimum_required(VERSION 3.26)
project(P2 C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(P2
        dynamic_list.c
        dynamic_list.h
        p3.c
        types.h)
