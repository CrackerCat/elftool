#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pthread.h>
#include "main.h"
#include "rc4.h"
#include "elfbase.h"
#include "ELFReader.h"
#include <map>


int main(int argv, char **args) {
    ELFReader elfReader("/Users/xiaobaiyey/AndroidStudioProjects/unpacker/app/build/outputs/apk/debug/libantihook.so");;
    elfReader.encryptSection(".text");
    return 0;
}