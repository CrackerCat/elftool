//
// Created by xiaobaiyey on 2018/7/15.
//

#include "ELFReader.h"
#include "rc4.h"

ELFReader::ELFReader(const char *path) {
    this->path = std::string(path);
    FILE *file = fopen(path, "rb");
    if (file == nullptr) {
        LOGE("open %s fail", path);
        return;
    }
    fseek(file, 0, SEEK_END);
    len = ftell(file);
    rewind(file);
    data = new u1[len];
    fread(data, len, 1, file);
    fclose(file);
    /*判断平台*/
    if (*(data + 4) == 1) {
        x64 = false;
    } else if (*(data + 4) == 2) {
        x64 = true;
    } else {
        LOGE("ERROR");
        return;
    }
    /*读取目标头文件*/
    /*读取目标section*/
    if (x64) {
        elf64_ehdr = (Elf64_Ehdr *) data;
        parse64Sections();
    } else {
        elf32_ehdr = (Elf32_Ehdr *) data;
        parse32Sections();
    }


}

bool ELFReader::is_x64() {
    return x64;
}

void ELFReader::parse32Sections() {
    u4 section_off = static_cast<u4>(getSectionOffset());
    u4 shroffset = static_cast<u4>(getShStrTabOffset());
    char *shrptr = reinterpret_cast<char *>(data + shroffset);
    u4 section_nums = getSectionNums();
    for (int i = 0; i < section_nums; ++i) {
        uint offset = sizeof(Elf32_Shdr) * i + section_off;
        Elf32_Shdr *elf32_shdr = (Elf32_Shdr *) (data + offset);
        char *sh_name = shrptr + elf32_shdr->sh_name;
        //printf("%s\n",sh_name);
        section32_map.insert(std::make_pair(sh_name, elf32_shdr));
    }
    printf("%s\n", "[+]parse sections over");
}

void ELFReader::parse64Sections() {
    u8 section_off = getSectionOffset();
    u8 shroffset = getShStrTabOffset();
    char *shrptr = reinterpret_cast<char *>(data + shroffset);
    u4 section_nums = getSectionNums();
    for (int i = 0; i < section_nums; ++i) {
        uint offset = sizeof(Elf64_Shdr) * i + section_off;
        Elf64_Shdr *elf64_shdr = (Elf64_Shdr *) (data + offset);
        char *sh_name = shrptr + elf64_shdr->sh_name;
        printf("%s\n", sh_name);
        section64_map.insert(std::make_pair(sh_name, elf64_shdr));
    }
    printf("%s\n", "[+]parse sections over");
}


u2 ELFReader::getSectionNums() {
    if (x64) {
        return elf64_ehdr->e_shnum;
    } else {
        return elf32_ehdr->e_shnum;
    }
}

u8 ELFReader::getSectionOffset() {
    if (x64) {
        return elf64_ehdr->e_shoff;
    } else {
        return elf32_ehdr->e_shoff;
    }
}

u8 ELFReader::getShStrTabOffset() {
    u8 section_off = getSectionOffset();
    if (x64) {
        Elf64_Shdr *ptr_offset = (Elf64_Shdr *) (section_off + data + sizeof(Elf64_Shdr) * elf64_ehdr->e_shstrndx);
        return ptr_offset->sh_offset;
    } else {
        Elf32_Shdr *ptr_offset = (Elf32_Shdr *) (section_off + data + sizeof(Elf32_Shdr) * elf32_ehdr->e_shstrndx);
        return ptr_offset->sh_offset;
    }

}

Elf32_Shdr *ELFReader::getSection32(const char *name) {
    Elf32_Shdr *section_ = nullptr;
    std::map<const char *, Elf32_Shdr *>::iterator iterator = section32_map.begin();
    for (iterator = section32_map.begin(); iterator != section32_map.end(); iterator++) {
        //printf("%s\n", iterator->first);
        if (strcmp(iterator->first, name) == 0) {
            section_ = iterator->second;
        }
    }
    return section_;
}

Elf64_Shdr *ELFReader::getSection64(const char *name) {
    Elf64_Shdr *section_ = nullptr;
    std::map<const char *, Elf64_Shdr *>::iterator iterator = section64_map.begin();
    for (iterator = section64_map.begin(); iterator != section64_map.end(); iterator++) {
        //printf("%s\n", iterator->first);
        if (strcmp(iterator->first, name) == 0) {
            section_ = iterator->second;
            break;
        }
    }
    return section_;
}

bool ELFReader::encryptSection(__const char *name) {

    if (x64) {
        Elf64_Shdr *section_ = getSection64(name);
        if (section_ == nullptr) {
            printf("%s\n", "cant find section");
            return false;
        }
        u8 section_len = section_->sh_size;
        u1 *section_data = data + section_->sh_offset;
        //u1 *section_data = data + section_->sh_offset;
        u1 key[16];
        memset(&key, 0, 16);
        memcpy(key, data, 16);
        rc4_state rc4State;
        rc4_setup(&rc4State, key, 16);
        rc4_crypt(&rc4State, section_data, len);
        printf("%s\n", "encrypt section over");
        elf64_ehdr->e_entry = section_->sh_offset;
        elf64_ehdr->e_shoff = section_len;
        cleanSectionInfo();
    } else {
        Elf32_Shdr *section_ = getSection32(name);
        if (section_ == nullptr) {
            printf("%s\n", "cant find section");
            return false;
        }
        u4 section_len = section_->sh_size;
        u1 *section_data = data + section_->sh_offset;
        u1 key[16];
        memset(&key, 0, 16);
        memcpy(key, data, 16);
        rc4_state rc4State;
        rc4_setup(&rc4State, key, 16);
        rc4_crypt(&rc4State, section_data, section_len);
        printf("%s\n", "encrypt section over");
        printf("0x%x 0x%x\n", section_->sh_offset, section_len);
        //头文件可用字节 https://blog.micblo.com/2018/02/10/Android-SO%E5%BA%93%E6%96%87%E4%BB%B6%E5%A4%B4%E5%88%86%E6%9E%90/
        elf32_ehdr->e_entry = section_->sh_offset;
        elf32_ehdr->e_flags = section_len;

        cleanSectionInfo();
    }

    writeToFile();
    return true;
}

bool ELFReader::cleanSectionInfo() {
    if (x64) {
        u8 section_off = getSectionOffset();
        u2 section_num = getSectionNums();
        u1 *section_data = data + section_off;
        u4 section_data_len = sizeof(Elf64_Shdr) * section_num;
        memset(section_data, 0, section_data_len);
    } else {
        Elf32_Shdr *section_ = nullptr;
        std::map<const char *, Elf32_Shdr *>::iterator iterator = section32_map.begin();
        for (iterator = section32_map.begin(); iterator != section32_map.end(); iterator++) {

            if (strcmp(iterator->first, ".dynamic") == 0 || strcmp(iterator->first, ".dynstr") == 0) {
                continue;
            } else {
                //清除信息
                printf("clear %s\n", iterator->first);
                memset(iterator->second, 0x0, sizeof(Elf32_Shdr));
            }
            //getShStrTabOffset();
        }
    }
    printf("clear section info over,you cant do anything\n");
    return true;

}

void ELFReader::writeToFile() {
    FILE *file = fopen(path.c_str(), "wb");
    fwrite(data, len, 1, file);
    fclose(file);
    printf("%s\n", "write file over");
}

