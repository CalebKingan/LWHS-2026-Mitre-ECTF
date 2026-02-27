"""
Author: Samuel Meyers
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import json
import argparse
import binascii
from dataclasses import dataclass


@dataclass
class Permission:
    """Represents a permission for one group
    """
    group_id: int=None
    read: bool=False
    write: bool=False
    receive: bool=False

    @classmethod
    def deserialize(cls, perms: str):
        group_id, perm_string = perms.split('=')

        perm_obj = cls(
            int(group_id, 16),
            read = perm_string[0] == 'R',
            write = perm_string[1] == 'W',
            receive = perm_string[2] == 'C',
        )
        return perm_obj

    def serialize(self):
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret

class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with.
    """
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ':'.join(perm.serialize() for perm in self)


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):
    secrets_obj = json.loads(secrets.decode())
    root_key_hex = secrets_obj.get("root_key", "")
    if len(root_key_hex) != 64:
        raise ValueError("global secrets missing 32-byte root_key")
    root_key = binascii.unhexlify(root_key_hex)

    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include <stdint.h>\n')
        f.write('#include "security.h"\n\n')
        f.write(f'#define HSM_PIN "{hsm_pin}"\n')
        f.write('#define ROOT_KEY_SIZE 32U\n\n')
        f.write('const static uint8_t GLOBAL_ROOT_KEY[ROOT_KEY_SIZE] = {\n')
        for i, byte in enumerate(root_key):
            suffix = '\n' if ((i + 1) % 8 == 0) else ' '
            f.write(f'0x{byte:02x},' + suffix)
        f.write('};\n\n')
        f.write("const static group_permission_t global_permissions[MAX_PERMS] = {\n")
        for perm in permissions:
            f.write(
                (f"\t{{{hex(perm.group_id)}, {str(perm.read).lower()}, "
                 f"{str(perm.write).lower()}, {str(perm.receive).lower()}}},\n")
            )
        f.write("};\n")
        f.write("\n#endif  // __SECRETS_H__\n")

if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", type=str, help="List of colon-separated permissions. E.g., \"1234=R--:4321=RWC\"")

        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())
