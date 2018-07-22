//
// Created by xiaobaiyey on 2018/7/15.
//

#ifndef UNTITLED_ELFREADER_H
#define UNTITLED_ELFREADER_H

#include "elfbase.h"
#include <map>
#include <string>

class ELFReader {
private:
    /*for 32 bit*/
    Elf32_Ehdr *elf32_ehdr;
    std::map<const char *, Elf32_Shdr *> section32_map;

    void parse32Sections();

    Elf64_Ehdr *elf64_ehdr;
    std::map<const char *, Elf64_Shdr *> section64_map;

    void parse64Sections();

    u1 *data;
    u4 len;
    bool x64 = false;
    std::string path;
public:
    ELFReader(const char *path);

    bool is_x64();

    bool encryptSection(__const char *name);

private:
    u8 getSectionOffset();

    u2 getSectionNums();

    u8 getShStrTabOffset();

    Elf32_Shdr *getSection32(const char *name);

    Elf64_Shdr *getSection64(const char *name);

    bool cleanSectionInfo();

    void writeToFile();
};


#endif //UNTITLED_ELFREADER_H
