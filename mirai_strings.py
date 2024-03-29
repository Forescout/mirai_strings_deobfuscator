'''
Copyright (C) 2023 Forescout Technologies, Inc.

Program License

"The Program" refers to any copyrightable work licensed under this License. Each
licensee is addressed as "you."

All rights granted under this License are granted for the term of copyright on
the Program, and are irrevocable provided the stated conditions are met. This
License explicitly affirms your unlimited permission to run the unmodified
Program for personal, governmental, business or non-profit use. You are
prohibited from using the Program in derivative works for commercial purposes.
You are prohibited from modifying the Program to be used in a commercial product
or service, either alone or in conjunction with other code, either downloadable
or accessed as a service. "Derivative works" shall mean any work, whether in
source or object form, that is based on (or derived from) the Program and for
which the editorial revisions, annotations, elaborations, or other modifications
represent, as a whole, an original work of authorship.

You may convey verbatim copies of the Program's source code as you receive it,
in any medium, provided that you conspicuously and appropriately publish on each
copy an appropriate copyright notice; keep intact all notices stating that this
License applies to the code; keep intact all notices of the absence of any
warranty; give all recipients a copy of this License along with the Program; and
do not financially benefit from the sale or other conveyance of the Program
either alone or in conjunction with other code, downloaded or accessed as a
service.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This License does not grant permission to use the trade names, trademarks,
service marks, or product names of the Licensor, except as required for
reasonable and customary use in describing the origin of the Program and
reproducing the content of the copyright notice.
'''

import sys
import string
import argparse
import traceback
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

# Just a bunch of previously used XOR keys
KNOWN_XOR_KEYS = [
    0x22, 0x17, 0x54, 0x3a, 0x04, 0x09, 0x37, 0x28
]

# A substitution cypher table used in one of Satori variants
TABLE_XOR_KEY = 0x59

TABLE_1 = [
    0x14, 0x15, 0x0a, 0x1d, 0x1f, 0x08, 0x0e, 0x00, 0x01, 0x17, 0x1a, 0x03, 0x0b,
    0x09, 0x16, 0x12, 0x1e, 0x10, 0x0c, 0x0d, 0x18, 0x1b, 0x0f, 0x11, 0x1c, 0x13,
    0x2d, 0x3f, 0x28, 0x36, 0x34, 0x38, 0x3c, 0x3a, 0x31, 0x35, 0x20, 0x37, 0x2c,
    0x3d, 0x2e, 0x2f, 0x33, 0x2b, 0x21, 0x30, 0x3e, 0x32, 0x23, 0x2a, 0x3b, 0x29,
    0x6e, 0x61, 0x60, 0x69, 0x6b, 0x6c, 0x6d, 0x68, 0x6f, 0x6a, 0x64, 0x19, 0x07,
    0x7d
]

TABLE_2 = [
    0x18, 0x1b, 0x1a, 0x1d, 0x1c, 0x1f, 0x1e, 0x11, 0x10, 0x13, 0x12, 0x15, 0x14,
    0x17, 0x16, 0x09, 0x08, 0x0b, 0x0a, 0x0d, 0x0c, 0x0f, 0x0e, 0x01, 0x00, 0x03,
    0x38, 0x3b, 0x3a, 0x3d, 0x3c, 0x3f, 0x3e, 0x31, 0x30, 0x33, 0x32, 0x35, 0x34,
    0x37, 0x36, 0x29, 0x28, 0x2b, 0x2a, 0x2d, 0x2c, 0x2f, 0x2e, 0x21, 0x20, 0x23,
    0x69, 0x68, 0x6b, 0x6a, 0x6d, 0x6c, 0x6f, 0x6e, 0x61, 0x60, 0x77, 0x76, 0x79,
    0x74
]

def xor_bytes(enc_str, xor_key):
    return [chr(x ^ xor_key) for x in enc_str]

def decrypt_with_substitution_tables(enc_str, table_1, table_2):
    dec_str = []
    x = 0
    while (x < len(enc_str)):
        for y in range(0,len(table_1)):
            if chr(enc_str[x]) == table_1[y]:
                dec_str.append(table_2[y])
        x += 1
    return dec_str

def get_stacked_strings(sequence, pattern, length, stop_char):
    strings = []
    string = []
    for i in range(len(sequence) - len(pattern) + 1):
        if sequence[i:i+len(pattern)] == pattern:
            last_element = sequence[i:i+length][-1]
            if last_element == stop_char:
                strings.append(string)
                string = []
            else:
                string.append(last_element)
    return strings

def search_elf_file_for_stacked_strings(binary_path, section_name='.text'):
    strings = []
    with open(binary_path, 'rb') as _file:
        elffile = ELFFile(_file)
        sec = elffile.get_section_by_name(section_name)
        if sec == None:
            raise ELFError(f'Failed to retrieve any data from the {section_name} section')
        strings = get_stacked_strings(list(sec.data()), [0xc6, 0x84, 0x24], 8, 0x00)
    return strings

def get_strings_from_section(binary_path, section_name='.rodata'):
    strings = None
    with open(binary_path, 'rb') as _file:
        elffile = ELFFile(_file)
        sec = elffile.get_section_by_name(section_name)
        strings = []
        string = []
        if sec == None:
            raise ELFError(f'Failed to retrieve any data from the {section_name} section')
        for byte in sec.data():
            if byte == 0x00:
                string.append(byte)
                if len(string) > 1:
                    strings.append(string)
                string = []
            else:
                string.append(byte)
    return strings

def print_plaintext_strings(hex_strings):
    for s in hex_strings:
        s_chr = [chr(x) for x in s]
        s = ''.join(s_chr)
        s = get_printable_string(s)
        if s != '':
            print(s)

def get_printable_string(hex_string):
    printable_chars = set(string.printable)
    hex_string = filter(lambda x: x in printable_chars, hex_string)
    hex_string = ''.join(hex_string).replace('\f', '').replace('\t', '').replace('\a', '').replace('\n', '')
    return hex_string

def print_strings_retrieved_with_known_keys(strings):
    for xor_key in KNOWN_XOR_KEYS:
        for s in strings:
            if len(s) < 3:
                continue

            decrypted_string = xor_bytes(s, xor_key)
            decrypted_string[len(decrypted_string)-1] = chr(ord(decrypted_string[len(decrypted_string)-1]) ^ xor_key)
            decrypted_string = get_printable_string(decrypted_string)
            if decrypted_string != '':
                print(decrypted_string)

def print_strings_retrieved_with_heuristics(strings):
    for s in strings:
        xor_key = s[len(s)-2]
        decrypted_string = xor_bytes(s, xor_key)
        decrypted_string[len(decrypted_string)-1] = chr(ord(decrypted_string[len(decrypted_string)-1]) ^ xor_key)
        decrypted_string = get_printable_string(decrypted_string)
        if decrypted_string != '':
            print(decrypted_string)

def print_strings_satori(strings):
    table_1_dec = [chr(x ^ TABLE_XOR_KEY) for x in TABLE_1]
    table_2_dec = [chr(x ^ TABLE_XOR_KEY) for x in TABLE_2]

    for s in strings:
        decrypted_string = decrypt_with_substitution_tables(s, table_1_dec, table_2_dec)
        decrypted_string = get_printable_string(decrypted_string)
        if decrypted_string != '':
            print(decrypted_string)

def print_strings_rapperbot(strings):
    for hex_str in strings:
        if hex_str != []:
            s = [chr(x) for x in hex_str]
            s = ''.join(s)
            s = get_printable_string(s)
            if s != '':
                print(s)

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--file_path', dest='file_path', type=str, default=None, help='The file path to the malware sample.')
    arg_parser.add_argument('--plain', dest='plain', action='store_true', help='Read the contents of .rodata and retrieve plaintext strings only.')
    arg_parser.add_argument('--known_keys', dest='known_keys', action='store_true', help='Read the contents of .rodata and de-obfuscate with known XOR keys.')
    arg_parser.add_argument('--heuristic', dest='heuristic', action='store_true', help='Read the contents of .rodata and de-obfuscate with heuristics.')
    arg_parser.add_argument('--satori', dest='satori', action='store_true', help='Read the contents of .rodata and de-obfuscate with the substitution table (some of Satori variants).')
    arg_parser.add_argument('--rapperbot', dest='rapperbot', action='store_true', help='Retrieve stacked strings (some of RapperBot variants, x86 only).')
    args = arg_parser.parse_args()

    try:
        if not args.file_path:
            print('ERROR: You must specify the file path of the malware sample to retrieve the strings from.')
            arg_parser.print_help()
            sys.exit(1)

        # If you don't specify any parameters, all de-obfuscation methods will be used
        if args.plain == args.known_keys == args.heuristic == args.satori == args.rapperbot == False:
            args.plain = args.known_keys = args.heuristic = args.satori = args.rapperbot = True

        if args.rapperbot:
            strings = search_elf_file_for_stacked_strings(args.file_path)
            if strings == None:
                print('ERROR: Failed to find strings in the .text section.')
            else:
                print_strings_rapperbot(strings)

        strings = get_strings_from_section(args.file_path, '.rodata')
        if strings == None:
            print('ERROR: Failed to find strings in the .rodata section.')
            sys.exit(1)

        if args.plain:
            print_plaintext_strings(strings)

        if args.known_keys:
            print_strings_retrieved_with_known_keys(strings)

        if args.heuristic:
            print_strings_retrieved_with_heuristics(strings)

        if args.satori:
            print_strings_satori(strings)

    except ELFError as elf_ex:
        print(f'ERROR while reading an ELF file "{args.file_path}": {elf_ex}')

    except Exception as generic_ex:
        print(f'ERROR: {generic_ex}')
        traceback.print_exc()
