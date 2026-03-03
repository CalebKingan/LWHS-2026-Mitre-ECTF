#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"

#define HSM_PIN "abc123"

static const unsigned char TRANSFER_KEY_SEED[16] = {0x71, 0xe4, 0xc2, 0x22, 0xfd, 0x2a, 0x61, 0xc1, 0xc7, 0x37, 0x61, 0xf4, 0x39, 0x3f, 0xf7, 0x99};

const static group_permission_t global_permissions[MAX_PERMS] = {
	{0x1111, false, true, false},
};

#endif  // __SECRETS_H__
