#!/usr/bin/python3


import os
import string
import sys

from datetime import datetime
from functools import singledispatch
from hashlib import md5, sha1, sha256

try:
    import pefile
except ImportError:
    exit(
		"pefile is not installed. Try 'pip install pefile' or see "
		"http://code.google.com/p/pefile/")

try:
    import magic
except ImportError:
    print(
		"python-magic is not installed (filetypes will not be available). "
		"Try 'pip install python-magic'")


def identify_filetype(name=None, data=None, mime=False):
    if not 'magic' in sys.modules:
        return None
    if name is not None:
        return magic.from_file(name, mime=mime)
    else:
        return magic.from_buffer(data, mime=mime)


@singledispatch
def _to_str(c):
    return c


@_to_str.register(str)
def _(c):
    if ord(c) == 0:
        c = ""
    return c


@_to_str.register(int)
def _(c):
    return _to_str(chr(c))


def _conv(s):
    return "".join([ _to_str(c) for c in s ])


class PeScan:
    def __init__(self, name=None, data=None):
        if name is None and data is None:
            raise ValueError("Must supply either name or data")

        if name is not None:
            pe = pefile.PE(name=name, fast_load=False)
        else:
            pe = pefile.PE(data=data, fast_load=False)

        self.__data__ = pe.__data__

        # Calculate the file size
        self.FILE_SIZE = len(self.__data__)

        # Attempt to identify the filetype
        self.FILETYPE = identify_filetype(data=pe.__data__[:1024])

        # Calculate the MD5 hash
        self.MD5_HASH = md5(self.__data__).hexdigest()

        # Calculate the SHA1 hash
        self.SHA1_HASH = sha1(self.__data__).hexdigest()

        # Calculate the SHA256 hash
        self.SHA256_HASH = sha256(self.__data__).hexdigest()

        # Calculate the import hash
        self.IMPORT_HASH = pe.get_imphash()

        # Retrieve the compile date timestamp
        date_timestamp = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)

        self.DATE_TIMESTAMP = date_timestamp.replace(microsecond=0).isoformat()

        # Calculate the CRC checksum and retrieve the CRC checksum found within 
        # the OPTIONAL_HEADER

        # https://msdn.microsoft.com/en-us/library/ms809762.aspx
        # CheckSum (dword) field in IMAGE_OPTIONAL_HEADER fields
        # Supposedly a CRC checksum of the file. As in other Microsoft executable 
        # formats, this field is ignored and set to 0. 
        # The one exception to this rule is for trusted services and these EXEs 
        # must have a valid checksum.
        self.CRC_CHECKSUM = dict()
        self.CRC_CHECKSUM['Claimed'] = hex(pe.OPTIONAL_HEADER.CheckSum)
        self.CRC_CHECKSUM['Actual'] = hex(pe.generate_checksum())
        self.CRC_CHECKSUM['Verified'] = pe.verify_checksum()

        # Retrieve PDB strings
        data = pe.get_data(
            pe.DIRECTORY_ENTRY_DEBUG[0].struct.AddressOfRawData,
            pe.DIRECTORY_ENTRY_DEBUG[0].struct.SizeOfData)

        self.PDB_PATH = _conv(pe.get_string_from_data(0x18, data))

        # Retrieve the entry point address
        # https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files

        # OPTIONAL_HEADER (AddressOfEntryPoint)
        # A pointer to the entry point function, relative to image base address. 
        # For executable files, this is the starting address. 
        # For device drivers, this is the initialization function. 
        # The entry point function is optional for DLLs. 
        # When no entry point is present, this member is zero."
        self.ENTRY_POINT = dict()

        if pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0:
            position = 0
            for section in pe.sections:
                position += 1
                addresses = range(section.VirtualAddress, section.VirtualAddress + section.Misc_VirtualSize + 1)
                if pe.OPTIONAL_HEADER.AddressOfEntryPoint in addresses:
                    name = _conv(section.Name)
                    break
            rva = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)
            raw = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + section.PointerToRawData - section.VirtualAddress)

            self.ENTRY_POINT['RVA'] = rva
            self.ENTRY_POINT['Raw'] = raw
            self.ENTRY_POINT['Name'] = name
            self.ENTRY_POINT['Position'] = position
            self.ENTRY_POINT['NumberOfSections'] = len(pe.sections)
        elif self.is_dll():
            self.ENTRY_POINT['Position'] = 0
        else:
            self.ENTRY_POINT = None


        # Retrieve any TLS (Thread Local Storage) callbacks
        # See Ero Carrera's blog http://blog.dkbza.org/2007/03/pe-trick-thread-local-storage.html for more info
        tls_callbacks = []

        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
            pe.DIRECTORY_ENTRY_TLS and \
            pe.DIRECTORY_ENTRY_TLS.struct and \
            pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            # Tested a bunch of binaries, including carved binaries (ie. possibility of corruption)
            # If AddressOfCallBacks < ImageBase, the initial RVA is negative 
            # which would -almost always- result in the following (or very similar) callback addresses:
            #  - 0x300
            #  - 0x400
            #  - 0xffff00
            #  - 0xb800
            # Given this, if AddressOfCallBacks < ImageBase, assume binary is corrupt and ignore
            if pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks > pe.OPTIONAL_HEADER.ImageBase:
                initial_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - \
                    pe.OPTIONAL_HEADER.ImageBase
                function = None
                index = 0
                while True:
                    try:
                        function = pe.get_dword_from_data(pe.get_data(initial_rva + 4 * index, 4), 0)
                    except pefile.PEFormatError:
                        break
                    if function == 0:
                        break
                    if function:
                        tls_callbacks.append([ hex(int(function)) ])
                    index+=1

        self.TLS_CALLBACKS = tls_callbacks

        # Retrieve the resource entries of a given PE file
        # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
        resources = []

        # Top-level directory table 'DIRECTORY_ENTRY_RESOURCE' found at 
        # beginning of resource section (.rsrc)
        # A series of tables, one for each group of nodes in the tree
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            # LEVEL 1
            # Top-level (TYPE) nodes
            # Entries in this table point to second-level tables
            for TYPE in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if not hasattr(TYPE, 'directory'):
                    continue
                # IMAGE_RESOURCE_DIRECTORY_ENTRY Format
                # Name field (dword) contains either an integer ID or a pointer 
                # to a structure that contains a string name.
                # If string name not present, integer ID used to search for 
                # known resource directory names.
                # Otherwise integer ID used as name
                if TYPE.name:
                    name = str(TYPE.name)
                elif pefile.RESOURCE_TYPE.get(TYPE.struct.Id):
                    name = str(pefile.RESOURCE_TYPE.get(TYPE.struct.Id))
                else:
                    name = str(TYPE.struct.Id)
                for ID in TYPE.directory.entries:
                    # LEVEL 2
                    # Second-level (ID) nodes
                    # Each second-level tree has the same Type ID but 
                    # different Langugage IDs
                    if not hasattr(ID, 'directory'):
                        continue
                    for LANGUAGE in ID.directory.entries:
                        # LEVEL 3
                        # Third-level (LANGUAGE) nodes
                        # Third-level trees have the same Type and Name IDs 
                        # but different Language IDs
                        OffsetToData = LANGUAGE.data.struct.OffsetToData
                        size = LANGUAGE.data.struct.Size
                        lang = pefile.LANG.get(
                            LANGUAGE.data.lang, 
                            'LANG_UNKNOWN').lstrip('LANG_')
                        sublang = pefile.get_sublang_name_for_lang(
                            LANGUAGE.data.lang, 
                            LANGUAGE.data.sublang).lstrip('SUBLANG_')
                        if lang in sublang:
                            language = sublang
                        else:
                            language = lang + "_" + sublang
                        try:
                            data = bytes(pe.get_data(OffsetToData, size))
                        except pefile.PEFormatError:
                            data = b""
                        filetype = identify_filetype(data=data).split(',')[0]

                        resources.append([
                            name,
                            hex(OffsetToData),
                            hex(size),
                            language,
                            filetype])

        self.RESOURCE_ENTRIES = resources

        # Retrieve any imported libraries and functions of a given PE file
        self.IMPORTED_LIBRARIES = dict()

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for library in pe.DIRECTORY_ENTRY_IMPORT:
                DLL = _conv(library.dll.upper())
                APIs = []
                for API in library.imports:
                    if API.name:
                        APIs.append(_conv(API.name))

                self.IMPORTED_LIBRARIES[DLL] = APIs

        # Retrieve any exported functions of a given PE file
        exports = []

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append([
                    f"{pe.OPTIONAL_HEADER.ImageBase + export.address:#010x}", 
                    _conv(export.name),
                    export.ordinal])

        self.EXPORTED_LIBRARIES = exports

        # Retrieve the sections of a given PE file
        characteristics = (
            [0x00000020, "CNT_CODE"],
            [0x00000040, "CNT_INIT_DATA"],
            [0x00000080, "CNT_UNINIT_DATA"],
            [0x10000000, "MEM_SHARED"],
            [0x20000000, "MEM_EXECUTE"],
            [0x40000000, "MEM_READ"],
            [0x80000000, "MEM_WRITE"])

        sections = []

        for section in pe.sections:
            flags = []

            name = _conv(section.Name)
            VirtualSize = hex(section.Misc_VirtualSize)
            VirtualAddress = hex(section.VirtualAddress)
            SizeOfRawData = hex(section.SizeOfRawData)
            entropy = round(section.get_entropy(), 1)

            for characteristic in characteristics:
                if section.Characteristics & characteristic[0]:
                    flags.append(characteristic[1])

            flags = ",".join(flags)

            sections.append([
                name,
                VirtualSize,
                VirtualAddress,
                SizeOfRawData,
                entropy,
                flags])

        self.SECTIONS = sections

        # Retrieve the version information of a given PE file
        version_information = []

        if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'FileInfo'):
            try:
                entries = pe.FileInfo[0][0].StringTable[0].entries
                entry   = pe.FileInfo[0][1].Var[0].entry
            except AttributeError:
                entries = pe.FileInfo[0][1].StringTable[0].entries
                entry   = pe.FileInfo[0][0].Var[0].entry

            entries.update(entry)

            for key, val in entries.items():
                version_information.append([_conv(key), _conv(val)])

        self.VERSION_INFORMATION = version_information

        del pe

