/*
 * packet.h -- Packet structure
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

struct clientid_t {
    uint8_t id[CLIENT_ID_SIZE];

} __attribute__((packed));

enum packetid_t {
    PACKET_PING_REQ = 0,
    PACKET_PING_RES = 1

};

// Ping packet
struct pingreq_t {
    uint8_t    magic;
    struct clientid_t client_id;
    uint8_t    nonce[crypto_box_NONCEBYTES];
    uint64_t   ping_id;
    uint8_t    padding[ENCRYPTION_PADDING];

} __attribute__((packed));

// Pong packet
struct pingres_t {
    uint8_t    magic;
    struct clientid_t client_id;
    uint8_t    nonce[crypto_box_NONCEBYTES];
    uint64_t   ping_id;
    uint8_t    padding[ENCRYPTION_PADDING];

} __attribute__((packed));
