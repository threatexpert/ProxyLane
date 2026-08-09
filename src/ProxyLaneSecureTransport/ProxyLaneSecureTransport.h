#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLST_ABI_VERSION 2u
#define PLST_OK 0
#define PLST_EOF 1
#define PLST_ERROR -1
#define PLST_WOULD_BLOCK -2
#define PLST_INVALID_ARGUMENT -3
#define PLST_BUFFER_TOO_SMALL -4

typedef void* PLST_SESSION;

uint32_t plst_abi_version(void);
int plst_session_create(const uint8_t* psk, size_t psk_len,
    const char* server_name, PLST_SESSION* session);
void plst_session_free(PLST_SESSION session);
int plst_session_is_ready(PLST_SESSION session);
int plst_session_feed_tls(PLST_SESSION session, const uint8_t* data,
    size_t data_len, size_t* consumed);
int plst_session_drain_tls(PLST_SESSION session, uint8_t* output,
    size_t output_capacity, size_t* written);
int plst_session_write_plain(PLST_SESSION session, const uint8_t* data,
    size_t data_len, size_t* written);
int plst_session_read_plain(PLST_SESSION session, uint8_t* output,
    size_t output_capacity, size_t* read);
int plst_session_send_close_notify(PLST_SESSION session);
int plst_session_export_key(PLST_SESSION session, uint8_t* output,
    size_t output_len);
int plst_session_last_error(PLST_SESSION session, char* output,
    size_t output_capacity);

int plst_udp_encrypt(const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* output, size_t output_capacity, size_t* written);
int plst_udp_decrypt(const uint8_t* key, size_t key_len,
    const uint8_t* packet, size_t packet_len,
    uint8_t* output, size_t output_capacity, size_t* written);

#ifdef __cplusplus
}
#endif
