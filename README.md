# Mirai strings deobfuscator

This tool provides a simple and easy way to retrieve obfuscated strings from
various Mirai variants: you simply need to run the script against a Mirai
sample, and you should get de-obfuscated strings as the output.

NOTE: the tool works only against unpacked samples (you'll need to use other
tools first, if the sample is packed with, e.g., UPX).

The purpose of the tool is our initial attempt to systematize the heuristics
for deobfuscating strings specific to various Mirai variants, and to create a
lightweight script that can be plugged into an automated malware analysis
pipeline. This tool does not attempt to replace [well-known general-purpose
tools for defeating XOR obfuscation](https://www.sans.org/blog/tools-for-examining-xor-obfuscation-for-malware-analysis/).

# Running the tool

Before running the tool for the first time, make sure you have installed all
the necessary packages:

```bash
pip install -r requirements.txt
```

To run the tool with all of the deobfuscation heuristics enabled (see a
description of each of them in the following subsections), simply run:

```bash
python mirai_strings.py --file_path [path_to_a_Mirai_sample]
```

The tool contains several running modes based various heuristics, we list them below.

## Plaintext strings

Sometimes the strings are not obfuscated, so if you need only that, you can
run:

```bash
python mirai_strings.py --file_path [path_to_a_Mirai_sample] --plain
```

Note that we only extract strings from the `.rodata` segment of a sample.

Alternatively, you can simply use the `strings` command line utility (it should
be available on all Unix systems by default).

## Apply known XOR keys

In this mode, the script will extract the contents of the `.rodata` segment of a
binary in question and apply the list of known XOR keys in an attempt to
de-obfuscate the strings. To do this, run the following command:

```bash
python mirai_strings.py --file_path [path_to_a_Mirai_sample] --known_keys
```

Note, that this list of XOR keys can be extended at any time.

## Try to infer unknown XOR keys based on the NULL-byte of an obfuscated string

Quite often, both obfuscated and de-obfuscated strings are NULL-terminated. This
means we can infer the XOR key from an obfuscated string without knowing it in
advance.

While this heuristic is not bulletproof, it's a nice fallback when everything
else fails. We apply this heuristic to the contents of the `.rodata` segment:

```bash
python mirai_strings.py --file_path [path_to_a_Mirai_sample] --heuristic
```

## Satori (substitution cypher)

Some of Satori variants that we captured used a different method of obfuscating
strings: XORed substitution tables. We have observed one example of such a table,
but this can be easily extended when the new ones are spotted in the wild.

To run the script in this mode, execute:

```bash
python mirai_strings.py --file_path [path_to_a_Mirai_sample] --satori
```
We apply this heuristic to the contents of the `.rodata` segment.

## RapperBot (strings hidden in the stack)

Some of the RapperBot variants build strings on the stack (these will be not
present in the `.rodata` segment, but will be found in the `.text` segment
instead). To run the script in a mode that attempts to retrieve such strings,
execute it as follows:

```bash
python mirai_strings.py --file_path [path_to_a_Mirai_sample] --rapperbot
```

Note, that this method will only work for samples build for the `x86` CPU
architecture. To support more architectures one could try to extend it by
adding architecture-specific opcode patterns.
