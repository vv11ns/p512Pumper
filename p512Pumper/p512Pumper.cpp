#include <iostream>
#include <Windows.h>

#include "E:\PROJECTS\p512.h"
PIMAGE_SECTION_HEADER PE_GetLastSectionHead(char* PEImage, PIMAGE_DOS_HEADER DOSHeader, PIMAGE_NT_HEADERS NTHeaders) {
    size_t IndexOfLastSection = NTHeaders->FileHeader.NumberOfSections - 1;
    PIMAGE_SECTION_HEADER LastSection = PIMAGE_SECTION_HEADER(PEImage + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (IndexOfLastSection * sizeof(IMAGE_SECTION_HEADER)));
    return LastSection;
}
int main()
{
    char inputfilepath[MAX_PATH + 1];
    char outputfilepath[MAX_PATH + 1];
    char* PEImage;
    ULONG SizeOfFile;
    ULONG NewSizeOfFile;
    SIZE_T PumpNeed;
    SIZE_T NewSectionSize;
    SIZE_T OldSectionSize;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS NTHeaders;
    PIMAGE_SECTION_HEADER LastSectionHeader;

    SetConsoleTitleA("Public PE Section Pumper");
    std::cout << "Coded by w11ns\nSpecially for public use\n";
    std::cout << "----------------------------------------------------\n\n";

    std::cout << "[?] PE FilePath: ";
    std::cin >> inputfilepath;
    std::cout << "[?] Output File Path: ";
    std::cin >> outputfilepath;
    std::cout << "[?] The number of required added kilobytes : ";
    std::cin >> PumpNeed;

    PEImage = (char*)p512file::ReadAllBytes(inputfilepath, &SizeOfFile);

    if (!PEImage || !SizeOfFile) {
        std::cout << "[!!!] File read error.\n";
        system("pause");
        return 0;
    }
    std::cout << "[!] File Size - " << SizeOfFile / 1024 << " kilobytes\n";
    DOSHeader = PIMAGE_DOS_HEADER(PEImage);
    NTHeaders = PIMAGE_NT_HEADERS(PEImage + DOSHeader->e_lfanew);
    if (DOSHeader->e_magic != 0x5A4D || NTHeaders->Signature != 0x00004550) {
        std::cout << "[!!!] File isn't PE.\n";
        system("pause");
        return 0;
    }
    if (NTHeaders->FileHeader.Machine != 0x014C) {
        std::cout << "[!!!] Only x86 PE files is supporting :(.\n";
        system("pause");
        return 0;
    }

    PumpNeed *= 1024;
    NewSizeOfFile = SizeOfFile + PumpNeed;
    std::cout << "[!] Result file size: " << NewSizeOfFile / 1024 << " kilobytes\n\n";

    LastSectionHeader = PE_GetLastSectionHead(PEImage, DOSHeader, NTHeaders);
    std::cout << "[!] Selected file section name : \"" << LastSectionHeader->Name << "\"\n";
    std::cout << "[!] Pumping...\n";

    OldSectionSize = LastSectionHeader->SizeOfRawData;
    NewSectionSize = OldSectionSize + PumpNeed;
    LastSectionHeader->SizeOfRawData = NewSectionSize;
    std::cout << "[!] Section Size : " << OldSectionSize << '\n';
    

    CHAR* AllocatedMemory = (CHAR*)VirtualAlloc(0, NewSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    int PumpPoint = LastSectionHeader->PointerToRawData + OldSectionSize;
    for (int i = 0; i < PumpPoint; ++i) {
        AllocatedMemory[i] = PEImage[i];
    }
    for (int i = PumpPoint; i < SizeOfFile; ++i) {
        AllocatedMemory[i + PumpNeed] = PEImage[i];
    }
    std::cout << "[!] New Section Size : " << NewSectionSize << '\n';

    std::cout << "[!] Writing File To \"" << outputfilepath << "\"...\n";
    p512file::WriteBytes(outputfilepath, AllocatedMemory, NewSizeOfFile);

    system("pause");
    return 0;
}