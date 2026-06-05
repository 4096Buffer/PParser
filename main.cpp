#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <ctime>
#include <capstone/capstone.h>

uint8_t* rvaToPtr(uint8_t* file_buffer_ptr, WORD sections_num, PIMAGE_SECTION_HEADER section_headers, DWORD rva) {
    for(int i = 0; i < sections_num; i++) {
        DWORD section_rva = section_headers[i].VirtualAddress;
        DWORD ptr_raw_data = section_headers[i].PointerToRawData;
        DWORD section_size = section_headers[i].Misc.VirtualSize;

        if(rva >= section_rva && rva < section_rva + section_size) {
            return file_buffer_ptr + ptr_raw_data + (rva - section_rva);
        }
    }

    return nullptr;
}

int main() {
    std::string filename;

    std::cout << "Pass a filename of the PE: ";
    std::cin >> filename;

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    
    if(!file.is_open()) {
        std::cout << "Couldnt open the file";
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> file_buffer(file_size);
    if(!file.read(reinterpret_cast<char*>(file_buffer.data()), file_size)) {
        std::cout << "[ERROR] Error while reading file.";
        return 1;
    }

    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(file_buffer.data());

    if(dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[ERROR] It's not valid PE. \n";
        return 1;
    }

    if(dos_header->e_lfanew + sizeof(IMAGE_DOS_HEADER) > file_size) {
        std::cout << "[ERROR] The PE structure is invalid!\n";
        return 1;
    }

    PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(file_buffer.data() + dos_header->e_lfanew);

    if(nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[ERROR] Invalid NT signature\n";
        return 1;
    }

    PIMAGE_FILE_HEADER file_header = &nt_headers->FileHeader;
    PIMAGE_OPTIONAL_HEADER optional_header = &nt_headers->OptionalHeader;

    time_t timestamp = file_header->TimeDateStamp;

    std::cout << "Machine: 0x" << std::hex << file_header->Machine << '\n';
    std::cout << "Timestamp: " << ctime(&timestamp) << '\n';

    PIMAGE_SECTION_HEADER section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<uint8_t*>(nt_headers) + 4 + sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader
    );

    for(int i = 0; i < file_header->NumberOfSections; i++) {
        std::cout << "Found section: ";        
        std::cout.write(reinterpret_cast<char*>(section_headers[i].Name), 8) << "\n\n";
        std::cout << "Virtual size: 0x" << std::hex <<  section_headers[i].Misc.VirtualSize << '\n';
        std::cout << "Offset from ImageBase: 0x" << std::hex << section_headers[i].VirtualAddress << '\n';
        std::cout << "Offset to raw data: 0x " << std::hex << section_headers[i].PointerToRawData << "\n\n";

        if(memcmp(section_headers[i].Name, ".text", 5) != 0) {
            continue;
        }

        uint8_t* ptr_data = file_buffer.data() + section_headers[i].PointerToRawData;
        DWORD size = section_headers[i].SizeOfRawData;

        csh handle;
        cs_insn *insn;

        cs_open(CS_ARCH_X86, CS_MODE_32, &handle);

        size_t count = cs_disasm(handle, ptr_data, size, section_headers[i].VirtualAddress + optional_header->ImageBase, 0, &insn);

        for(size_t i = 0; i < count; i++) {
            std::cout << insn[i].mnemonic << " " << insn[i].op_str << '\n';
        }

        cs_free(insn, count);
        cs_close(&handle);
    }

    IMAGE_DATA_DIRECTORY dir_data = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        rvaToPtr(file_buffer.data(), file_header->NumberOfSections, section_headers, dir_data.VirtualAddress)
    );

    if(import_desc == nullptr) {
        std::cout << "[INFO] No dlls were found.\n";
    } else {
        while(import_desc->Name != 0) {
            std::cout << "Found dll: " << reinterpret_cast<char*>(rvaToPtr(file_buffer.data(), file_header->NumberOfSections, section_headers, import_desc->Name)) << '\n';
            import_desc++;
        }
    }

    std::cin.ignore();
    std::cin.get();
}