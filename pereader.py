import sys
import pefile
import peutils

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def main():
    if len(sys.argv) != 2:
        print("Invalid usage: please enter 1 PE formatted file")
        return
    
    pe = pefile.PE(sys.argv[1])
    if not pe:
        print(bcolors.FAIL + "NOT A PE FORMATTED FILE" + bcolors.ENDC)
        return
    
    print(bcolors.HEADER + "~~~~ Beginning Static Analysis ~~~~" + bcolors.ENDC)

    # determine the file type
    if pe.is_dll():
        print("This program is a DLL\n")
    elif pe.is_exe():
        print("This program is a EXE\n")
    else:
        print("This program is a SYS\n")

    # number of imported resources and functions
    print(f"The program has {len(pe.DIRECTORY_ENTRY_IMPORT)} imports\n")

    total_imports = 0

    for iid in pe.DIRECTORY_ENTRY_IMPORT:
        total_imports += len(iid.imports)

    print(f"The program has {total_imports} imported functions\n")

    # Compile time
    date_with_extra = pe.FILE_HEADER.dump_dict()["TimeDateStamp"]["Value"]
    date = date_with_extra[date_with_extra.index("["): ]
    print(bcolors.OKCYAN + f"Compiled at: {date}\n" + bcolors.ENDC)


    # Verify header checksum
    if(pe.verify_checksum()):
        print(bcolors.OKGREEN + "CHECKSUM VERIFIED\n" + bcolors.ENDC)
    else:
        print(bcolors.FAIL + "CHECKSUM FAILED\n" + bcolors.ENDC)

    # Find matches in the PEiD databse
    with open('./UserDB.TXT', 'rb') as sig_file:
        sig_data = sig_file.read().decode('ISO-8859-1')

    signatures = peutils.SignatureDatabase(data=sig_data)

    matches = signatures.match_all(pe, ep_only = True)
    print(f"Matches with PEiD databse: {matches}")
    
    print(bcolors.BOLD + "Starting section iteration\n" + bcolors.ENDC)

    # Check for entry point and section stuff
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    has_rsrc = False

    for section in pe.sections:
        name = section.Name.decode("utf-8")
        print(bcolors.OKBLUE + f"~~ Current section - {name} ~~~ \n" + bcolors.ENDC)

        if section.SizeOfRawData == 0:
            print(bcolors.WARNING + "THIS SECTION HAS A SIZE OF 0\n" + bcolors.ENDC)

        entropy = section.get_entropy()

        print(f"This sections entropy is {entropy}")

        if(entropy > 6.8):
            print(bcolors.WARNING + "THIS SECTIONS ENTROPY IS HIGH - THIS COULD BE PACKED" + bcolors.ENDC)

        if(section.contains_offset(entry_point)):
            print(bcolors.OKGREEN + "THIS SECTION CONTAINS THE ENTRY POINT" + bcolors.ENDC)
            if not (".text" in name or ".code" in name or "CODE" in name or  "INIT" in name):
                print(bcolors.WARNING + "THIS SECTION IS NOT A NORMAL ENTRY POINT SECTION" + bcolors.ENDC)

        if(".rsrc" in name):
            has_rsrc = True
    
    if(has_rsrc):
        resource_type = pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
        resource_id = resource_type.directory.entries[0]
        resource_lang = resource_id.directory.entries[0]
        offset_to_data = resource_lang.data.struct.OffsetToData
        size = resource_lang.data.struct.Size

        data = pe.get_data(offset_to_data, size)

        with open('rsrc.bin', 'wb') as file:
            file.write(data)


if __name__=="__main__":
    main()