#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"

#define HSM_PIN "abc123"

const static uint8_t TRANSFER_KEY[16] = {
	0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

const static group_permission_t global_permissions[MAX_PERMS] = {
	{0x1111, false, true, false},
};

#endif  // __SECRETS_H__
