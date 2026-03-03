/**
 * @file commands.c
 * @author Lakota West High School eCTF Team (Original Design Samuel Meyers)
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "crypto.h"
#include <stddef.h>
#include <string.h>

static bool is_name_sanitized(const char *name) {
    bool has_terminator = false;

    for (uint8_t i = 0; i < MAX_NAME_SIZE; i++) {
        char c = name[i];

        if (c == '\0') {
            has_terminator = true;
            continue;
        }

        if ((uint8_t)c < 0x20 || (uint8_t)c > 0x7E) {
            return false;
        }
    }

    return has_terminator;
}

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;
static union {
    read_response_t read_file_response;
    receive_response_t transfer_file_response;
} command_io_buffer;

/* Avoid large per-call stack allocations during transfer crypto paths. */
static uint8_t transfer_work_buffer[MAX_CONTENTS_SIZE];

static uint16_t transfer_crypto_len(uint16_t contents_len)
{
    uint16_t bounded_len = contents_len;

    if (bounded_len > MAX_CONTENTS_SIZE) {
        bounded_len = MAX_CONTENTS_SIZE;
    }

    if (bounded_len == 0U) {
        return BLOCK_SIZE;
    }

    uint16_t rem = bounded_len % BLOCK_SIZE;
    if (rem == 0U) {
        return bounded_len;
    }

    return (uint16_t)(bounded_len + (BLOCK_SIZE - rem));
}

#define TRANSFER_AAD_SIZE (UUID_SIZE + sizeof(group_id_t) + sizeof(uint16_t) + sizeof(uint64_t) + 1U)

static void store_le16(uint8_t out[2], uint16_t v)
{
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
}

static void store_le64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static void build_transfer_aad(uint8_t aad[TRANSFER_AAD_SIZE],
                               const uint8_t uuid[UUID_SIZE],
                               group_id_t group_id,
                               uint16_t contents_len,
                               uint64_t counter)
{
    uint16_t off = 0U;

    memset(aad, 0, TRANSFER_AAD_SIZE);
    memcpy(&aad[off], uuid, UUID_SIZE);
    off += UUID_SIZE;

    store_le16(&aad[off], group_id);
    off += sizeof(group_id_t);

    store_le16(&aad[off], contents_len);
    off += sizeof(uint16_t);

    store_le64(&aad[off], counter);
    off += sizeof(uint64_t);

    aad[off] = (uint8_t)RECEIVE_MSG;
}

static uint16_t transfer_response_len_from_ct_len(uint16_t ct_len)
{
    return (uint16_t)(offsetof(receive_response_t, blob.ciphertext) + ct_len);
}

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    typedef struct {
        uint32_t in_use;
        group_id_t group_id;
        char name[MAX_NAME_SIZE];
    } file_list_header_t;

    file_list->n_files = 0;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        const filesystem_entry_t *entry = get_file_metadata(i);
        file_list_header_t file_header;

        if (entry == NULL || file_list->n_files >= MAX_FILE_COUNT) {
            continue;
        }

        if (entry->length < offsetof(file_t, contents) || entry->length > STORED_FILE_SIZE) {
            continue;
        }

        if (entry->flash_addr != FILE_START_PAGE_FROM_SLOT(i)) {
            continue;
        }

        memset(&file_header, 0, sizeof(file_header));
        flash_read(entry->flash_addr, &file_header, sizeof(file_header));

        // Check if the file is in use using header metadata only.
        if (file_header.in_use == FILE_IN_USE) {
            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = file_header.group_id;
            memcpy(file_list->metadata[file_list->n_files].name, file_header.name, MAX_NAME_SIZE);
            file_list->n_files++;
        }
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    if (pkt_len != sizeof(list_command_t)) {
        print_error("Malformed list request");
        return -1;
    }

    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    if (pkt_len != sizeof(read_command_t)) {
        print_error("Malformed read request");
        return -1;
    }

    read_command_t *command = (read_command_t*)buf;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (command->slot >= MAX_FILE_COUNT) {
        print_error("Invalid slot");
        return -1;
    }

    // zeroizing memory is a pretty good practice
    memset(&command_io_buffer.read_file_response, 0, sizeof(read_response_t));

    if (read_file(command->slot, &current_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }
    // copy structure of the persistent file
    memcpy(command_io_buffer.read_file_response.name, &current_file.name, MAX_NAME_SIZE);
    uint16_t out_len = current_file.contents_len;
    if (out_len > MAX_CONTENTS_SIZE) out_len = MAX_CONTENTS_SIZE;

    memcpy(command_io_buffer.read_file_response.contents, current_file.contents, out_len);
    pkt_len_t length = MAX_NAME_SIZE + out_len;

    if (!validate_permission(current_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // write a success message with the file information
    write_packet(CONTROL_INTERFACE, READ_MSG, &command_io_buffer.read_file_response, length);
    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    if (pkt_len < sizeof(write_command_t) - MAX_CONTENTS_SIZE) {
        print_error("Malformed write request");
        return -1;
    }

    write_command_t *command = (write_command_t*)buf;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    if (command->slot >= MAX_FILE_COUNT) {
        print_error("Invalid slot");
        return -1;
    }

    if (command->contents_len > MAX_CONTENTS_SIZE) {
        print_error("Invalid content size");
        return -1;
    }

    if (pkt_len != (sizeof(write_command_t) - MAX_CONTENTS_SIZE + command->contents_len)) {
        print_error("Mismatched write length");
        return -1;
    }

    if (!is_name_sanitized(command->name)) {
        print_error("Invalid file name");
        return -1;
    }

    create_file(
        &current_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    // Store the file persistently
    if (write_file(command->slot, &current_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    if (pkt_len != sizeof(receive_command_t)) {
        print_error("Malformed receive request");
        return -1;
    }

    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    uint8_t aad[TRANSFER_AAD_SIZE];
    uint8_t transfer_key[KEY_SIZE];
    uint16_t expected_len;
    uint16_t crypto_len;
    uint64_t last_seen_counter;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (command->read_slot >= MAX_FILE_COUNT || command->write_slot >= MAX_FILE_COUNT) {
        print_error("Invalid slot");
        return -1;
    }

    memset(&command_io_buffer.transfer_file_response, 0, sizeof(command_io_buffer.transfer_file_response));
    memset(&request, 0, sizeof(request));

    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    len_recv_msg = sizeof(command_io_buffer.transfer_file_response);
    if (read_packet(TRANSFER_INTERFACE, &cmd, &command_io_buffer.transfer_file_response, &len_recv_msg) != MSG_OK) {
        print_error("Failed to receive response");
        return -1;
    }

    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    if (command_io_buffer.transfer_file_response.contents_len > MAX_CONTENTS_SIZE) {
        print_error("Malformed receive response contents length");
        return -1;
    }

    crypto_len = transfer_crypto_len(command_io_buffer.transfer_file_response.contents_len);
    if (command_io_buffer.transfer_file_response.blob.ct_len != crypto_len) {
        print_error("Malformed receive response ciphertext length");
        return -1;
    }

    expected_len = transfer_response_len_from_ct_len(command_io_buffer.transfer_file_response.blob.ct_len);
    if (len_recv_msg != expected_len) {
        print_error("Malformed receive response packet length");
        return -1;
    }

    if (get_last_seen_counter(&last_seen_counter) != 0) {
        print_error("Failed to load replay state");
        return -1;
    }
    if (command_io_buffer.transfer_file_response.blob.counter <= last_seen_counter) {
        print_error("Replay detected");
        return -1;
    }

    if (get_or_create_transfer_key(transfer_key) != 0) {
        print_error("Failed to load transfer key");
        return -1;
    }

    build_transfer_aad(aad,
                       command_io_buffer.transfer_file_response.uuid,
                       command_io_buffer.transfer_file_response.group_id,
                       command_io_buffer.transfer_file_response.contents_len,
                       command_io_buffer.transfer_file_response.blob.counter);

    if (decrypt_transfer_gcm(command_io_buffer.transfer_file_response.blob.ciphertext,
                             command_io_buffer.transfer_file_response.blob.ct_len,
                             transfer_key,
                             command_io_buffer.transfer_file_response.blob.nonce,
                             aad,
                             TRANSFER_AAD_SIZE,
                             command_io_buffer.transfer_file_response.blob.tag,
                             transfer_work_buffer) != 0) {
        print_error("Failed to authenticate transfer contents");
        return -1;
    }

    if (!validate_permission(command_io_buffer.transfer_file_response.group_id, PERM_RECEIVE)) {
        print_error("Permission denied: cannot receive this group");
        return -1;
    }

    if (set_last_seen_counter(command_io_buffer.transfer_file_response.blob.counter) != 0) {
        print_error("Failed to persist replay state");
        return -1;
    }

    if (create_file(&current_file,
                    command_io_buffer.transfer_file_response.group_id,
                    command_io_buffer.transfer_file_response.name,
                    command_io_buffer.transfer_file_response.contents_len,
                    transfer_work_buffer) < 0) {
        print_error("Failed to build received file");
        return -1;
    }

    if (write_file(command->write_slot, &current_file, command_io_buffer.transfer_file_response.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    if (pkt_len != sizeof(interrogate_command_t)) {
        print_error("Malformed interrogate request");
        return -1;
    }

    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    // pin check
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    len_recv_msg = sizeof(final_list_buf);

    // recieve the response message
    if (read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg) != MSG_OK) {
        print_error("Failed to receive interrogate response");
        return -1;
    }

    if (len_recv_msg > sizeof(final_list_buf)){
         print_error("Malformed interrogate response length");
        return -1;
    }
    
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }


    // Filter neighbor list to only groups we have RECEIVE permission for
    list_response_t filtered;
    memset(&filtered, 0, sizeof(filtered));

    for (uint8_t i = 0; i < final_list_buf.n_files; i++) {
        if (validate_permission(final_list_buf.metadata[i].group_id, PERM_RECEIVE)) {
            filtered.metadata[filtered.n_files++] = final_list_buf.metadata[i];
        }
    }

    // Return filtered list to the user
    pkt_len_t out_len = LIST_PKT_LEN(filtered.n_files);
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &filtered, out_len);
    return 0;
}


/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    // Best-effort helper to ensure requester receives a transfer response.
    // This prevents peer receive operations from hanging on denied/error paths.
    #define SEND_TRANSFER_ERROR(msg) do { \
        print_error(msg); \
        write_packet(TRANSFER_INTERFACE, ERROR_MSG, NULL, 0); \
        return -1; \
    } while (0)

    // Receive a packet from a neighboring hsm
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG:
            // zeroize the buffers we will use
            memset(&file_list, 0, sizeof(file_list));

            // generate a list of files for the other device
            generate_list_files(&file_list);

            // TODO: the reference design does not implement *ANY* security
            // you will want to add something here to comply with SR1

            // send the list of files on this device
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;
        case RECEIVE_MSG: {
            uint8_t transfer_key[KEY_SIZE];
            uint8_t aad[TRANSFER_AAD_SIZE];
            uint16_t crypto_len;
            uint64_t counter;

            if (read_length != sizeof(receive_request_t)) {
                SEND_TRANSFER_ERROR("Malformed receive transfer request");
            }

            command = (receive_request_t *)uart_buf;

            if (command->slot >= MAX_FILE_COUNT) {
                SEND_TRANSFER_ERROR("Invalid slot in transfer request");
            }

            if (read_file(command->slot, &current_file) < 0) {
                SEND_TRANSFER_ERROR("Failed to read file");
            }

            bool allowed = false;
            for (int i = 0; i < MAX_PERMS; i++) {
                if (command->permissions[i].group_id == current_file.group_id &&
                    command->permissions[i].receive) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                SEND_TRANSFER_ERROR("Requester lacks RECEIVE permission for this group");
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                SEND_TRANSFER_ERROR("Getting metadata failed");
            }

            if (get_or_create_transfer_key(transfer_key) != 0) {
                SEND_TRANSFER_ERROR("Failed to load transfer key");
            }

            if (get_and_increment_transfer_counter(&counter) != 0) {
                SEND_TRANSFER_ERROR("Failed to update transfer counter");
            }

            crypto_len = transfer_crypto_len(current_file.contents_len);
            memset(&command_io_buffer.transfer_file_response, 0, sizeof(command_io_buffer.transfer_file_response));
            memcpy(command_io_buffer.transfer_file_response.uuid, metadata->uuid, UUID_SIZE);
            command_io_buffer.transfer_file_response.group_id = current_file.group_id;
            memcpy(command_io_buffer.transfer_file_response.name, current_file.name, MAX_NAME_SIZE);
            command_io_buffer.transfer_file_response.contents_len = current_file.contents_len;
            command_io_buffer.transfer_file_response.blob.counter = counter;
            command_io_buffer.transfer_file_response.blob.ct_len = crypto_len;

            if (security_rng_generate(command_io_buffer.transfer_file_response.blob.nonce, TRANSFER_GCM_NONCE_SIZE) != 0) {
                SEND_TRANSFER_ERROR("Failed to generate nonce");
            }

            memset(transfer_work_buffer, 0, crypto_len);
            memcpy(transfer_work_buffer, current_file.contents, current_file.contents_len);

            build_transfer_aad(aad,
                               command_io_buffer.transfer_file_response.uuid,
                               command_io_buffer.transfer_file_response.group_id,
                               command_io_buffer.transfer_file_response.contents_len,
                               command_io_buffer.transfer_file_response.blob.counter);

            if (encrypt_transfer_gcm(transfer_work_buffer,
                                     crypto_len,
                                     transfer_key,
                                     command_io_buffer.transfer_file_response.blob.nonce,
                                     aad,
                                     TRANSFER_AAD_SIZE,
                                     command_io_buffer.transfer_file_response.blob.ciphertext,
                                     command_io_buffer.transfer_file_response.blob.tag) != 0) {
                SEND_TRANSFER_ERROR("Failed to encrypt transfer contents");
            }

            write_length = transfer_response_len_from_ct_len(command_io_buffer.transfer_file_response.blob.ct_len);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &command_io_buffer.transfer_file_response, write_length);
            break;
        }
        default:
            SEND_TRANSFER_ERROR("Bad message type");
    }

    #undef SEND_TRANSFER_ERROR

    // blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
