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

static void derive_transfer_key(uint8_t *key_out) {
    const char transfer_key_seed[] = HSM_PIN;
    const size_t seed_len = sizeof(transfer_key_seed) - 1U;

    memset(key_out, 0, KEY_SIZE);
    if (seed_len == 0U) {
        return;
    }

    for (size_t i = 0; i < KEY_SIZE; i++) {
        key_out[i] = (uint8_t)transfer_key_seed[i % seed_len];
    }
}

static int transform_transfer_contents(uint8_t *contents, bool encrypting) {
    uint8_t key[KEY_SIZE];
    int result;

    if (contents == NULL) {
        return -1;
    }

    derive_transfer_key(key);
    if (encrypting) {
        result = encrypt_sym(contents, MAX_CONTENTS_SIZE, key, contents);
    } else {
        result = decrypt_sym(contents, MAX_CONTENTS_SIZE, key, contents);
    }

    if (result != 0) {
        return result;
    }
    return 0;
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

    // zeroize the buffers we will use
    memset(&command_io_buffer.transfer_file_response, 0, sizeof(command_io_buffer.transfer_file_response));
    memset(&request, 0, sizeof(request));

    // prep request to neighbor
    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    // request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    // limits receiving message size
    len_recv_msg = sizeof(command_io_buffer.transfer_file_response);

    //receive the response message
    if (read_packet(TRANSFER_INTERFACE, &cmd, &command_io_buffer.transfer_file_response, &len_recv_msg) != MSG_OK) {
        print_error("Failed to receive response");
        return -1;
    }
    if (len_recv_msg != sizeof(command_io_buffer.transfer_file_response)){
         print_error("Malformed recieved response length");
        return -1;
    }
    
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    if (transform_transfer_contents(command_io_buffer.transfer_file_response.file.contents, false) != 0) {
        print_error("Failed to decrypt transfer contents");
        return -1;
    }
    
    // Enforce local receive permission before writing file
    if (!validate_permission(command_io_buffer.transfer_file_response.file.group_id, PERM_RECEIVE)) {
        print_error("Permission denied: cannot receive this group");
        return -1;
    }


    // write that file into the file system
    if (write_file(command->write_slot, &command_io_buffer.transfer_file_response.file, command_io_buffer.transfer_file_response.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }
    // empty success message
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
            if (read_length != sizeof(receive_request_t)) {
                SEND_TRANSFER_ERROR("Malformed receive transfer request");
            }

            command = (receive_request_t *)uart_buf;

            if (command->slot >= MAX_FILE_COUNT) {
                SEND_TRANSFER_ERROR("Invalid slot in transfer request");
            }

            // Read the requested file first so we know its group_id
            if (read_file(command->slot, &command_io_buffer.transfer_file_response.file) < 0) {
                SEND_TRANSFER_ERROR("Failed to read file");
            }

            // Enforce requester's RECEIVE permission before sending file
            bool allowed = false;
            for (int i = 0; i < MAX_PERMS; i++) {
                if (command->permissions[i].group_id == command_io_buffer.transfer_file_response.file.group_id &&
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

            memcpy(&command_io_buffer.transfer_file_response.uuid, &metadata->uuid, UUID_SIZE);

            if (transform_transfer_contents(command_io_buffer.transfer_file_response.file.contents, true) != 0) {
                SEND_TRANSFER_ERROR("Failed to encrypt transfer contents");
            }

            write_length = sizeof(receive_response_t);
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
