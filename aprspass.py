#!/usr/bin/python

# Generate APRS-IS passcode from CALLSIGN
# algorithm from Xastir callpass.c

kKEY = 0x73e2

def doHash(callsign):
    rootCall = callsign.split("-")[0].upper() + '\0'    # Strip ssid part from call and convert to uppercase.

    hash = kKEY  # Initialize with the key value
    i = 0

    for i in range(0, len(rootCall) - 1, 2):    # Loop through the string two bytes at a time
        hash ^= ord(rootCall[i]) << 8    # xor high byte with accumulated hash
        hash ^= ord(rootCall[i + 1])    # xor low byte with accumulated hash
        i += 2

    return int(hash & 0x7fff)    # mask off the high bit so number is always positive


if __name__ == '__main__':
    from sys import argv
    import re

    if len(argv) > 1:
        if re.match("([1-9][A-Z][A-Z]+[0-9]|[A-Z][2-9A-Z]?[0-9])[A-Z]{1,4}", argv[1].upper(), flags=0):
            print('%d' % doHash(argv[1]))
            exit(0)
        else:
            print('Bad Callsign')
            exit(1)
    else:
        print('Usage: python ./aprspass.py <callsign[-ssid]>')
        exit(1)
