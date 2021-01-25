#include "../Vendor.hpp"

static const constexpr char banner[] = ""
"#######################################\n"
"# UWPLoad                             #\n"
"#                                     #\n"
"# Please input valid arguments        #\n"
"# (a valid process id and library)    #\n"
"#######################################\n";

int elevate(const char* image);
int inject(const char* image, DWORD process);

int main(int argc, char **argv) {
    if(argc < 3) {
        printf("%s", banner);
        return -1;
    }

    switch(elevate(argv[2])) {
        case 1:
            printf("GetNamedSecurityInfo Failed.\n");
            return -1;
        case 2:
            printf("ConvertStringSidToSid Failed.\n");
            return -1;
        case 3:
            printf("SetEntriesInAcl Failed.\n");
            return -1;
        case 4:
            printf("SetNamedSecurityInfo Failed.\n");
            return -1;
        default:
            printf("Permissions set.\n");
    }

    switch(inject(argv[2], strtol(argv[1], nullptr, 0))) {
        case 1:
            printf("LoadLibraryA Failed.\n");
            return -1;
        case 2:
            printf("OpenProcess Failed.\n");
            return -1;
        case 3:
            printf("VirtualAllocEx Failed.\n");
            return -1;
        case 4:
            printf("WriteProcessMemory Failed.\n");
            return -1;
        case 5:
            printf("CreateRemoteThread Failed.\n");
            return -1;
        default:
             printf("Injected.\nYou may now close this window.\n");
    }
    return 0;
}

int elevate(const char* image) {
    PSID sid;
    PACL dacl;
    PACL newDacl;
    EXPLICIT_ACCESS eAccess;
    PSECURITY_DESCRIPTOR sd;

    if(GetNamedSecurityInfo(image, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd)) {
        LocalFree(sd);
        return 1;
    }

    if(!ConvertStringSidToSid("S-1-15-2-1", &sid)) {
        return 2;
    }

    RtlSecureZeroMemory(&eAccess, sizeof(eAccess));
    eAccess.grfAccessPermissions = GENERIC_ALL;
    eAccess.grfAccessMode = SET_ACCESS;
    eAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    eAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    eAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    eAccess.Trustee.ptstrName = (LPCH)sid;

    if(SetEntriesInAcl(1, &eAccess, dacl, &newDacl)) {
        LocalFree(sid);
        return 3;
    }

    if(SetNamedSecurityInfo(const_cast<char*>(image), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr)) {
        LocalFree(newDacl);
        return 4;
    }
    LocalFree(newDacl);
    return 0;
}

int inject(const char* image, const DWORD process) {
    const auto LoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if(!LoadLibraryA) { return 1; }
    const auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, process);
    if(!ProcessHandle) { return 2; }
    const auto remote = VirtualAllocEx(ProcessHandle, nullptr, strlen(image), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(!remote) { return 3; }
    const auto wpm = WriteProcessMemory(ProcessHandle, remote, image, strlen(image), nullptr);
    if(!wpm) { return 4; }
    const auto crt = CreateRemoteThread(ProcessHandle, nullptr, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, (LPVOID)remote, NULL, nullptr);
    if(!crt) { return 5; }
    return 0;
}
