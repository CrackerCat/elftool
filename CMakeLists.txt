cmake_minimum_required(VERSION 3.10)
project(untitled)

set(CMAKE_CXX_STANDARD 11)

add_executable(untitled main.cpp rc4.cpp ELFReader.cpp ELFReader.h)