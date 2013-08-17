/*
 * ping.c -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h"
#include "net_crypto.h"
#include "packets.h"
#include "network.h"
#include "util.h"

#define PING_NUM_MAX 256
#define PING_TIMEOUT 5 // 5s

struct pinged_t {
    struct IP_Port  ipp;
    uint64_t id;
    uint64_t timestamp;
};

static struct pinged_t    pings[PING_NUM_MAX];
static size_t      num_pings;
static size_t      pos_pingst;
static struct clientid_t *self_id = (struct clientid_t *) &self_public_key;

extern uint8_t self_secret_key[crypto_box_SECRETKEYBYTES]; // DHT.c

void init_ping()
{
    num_pings = 0;
    pos_pings = 0;
}

static bool is_timeout(uint64_t time)
{
    return (time + PING_TIMEOUT) < now();
}

static void remove_timeouts()   // O(n)
{
    size_t i, id;
    size_t new_pos = pos_pings;
    size_t new_num = num_pings;

    // Loop through buffer, oldest first
    for (i = 0; i < num_pings; i++) {
        id = (pos_pings + i) % PING_NUM_MAX;

        if (is_timeout(pings[id].timestamp)) {
            new_pos++;
            new_num--;
        }
        // Break here because list is sorted.
        else {
            break;
        }
    }

    num_pings = new_num;
    pos_pings = new_pos % PING_NUM_MAX;
}

uint64_t add_ping(struct IP_Port ipp) // O(n)
{
    size_t p;

    remove_timeouts();

    // Remove oldest ping if full buffer
    if (num_pings == PING_NUM_MAX) {
        num_pings--;
        pos_pings = (pos_pings + 1) % PING_NUM_MAX;
    }

    // Insert new ping at end of list
    p = (pos_pings + num_pings) % PING_NUM_MAX;

    pings[p].ipp       = ipp;
    pings[p].timestamp = now();
    pings[p].id        = random_64b();

    num_pings++;
    return pings[p].id;
}

bool is_pinging(struct IP_Port ipp, uint64_t ping_id)   // O(n) TODO: replace this with something else.
{
    if (ipp.ip.i == 0 && ping_id == 0)
        return false;

    size_t i, id;

    remove_timeouts();

    for (i = 0; i < num_pings; i++) {
        id = (pos_pings + i) % PING_NUM_MAX;

        // ping_id = 0 means match any id
        if ((ipp_eq(pings[id].ipp, ipp) || ipp.ip.i == 0) && (pings[id].id == ping_id || ping_id == 0)) {
            return true;
        }
    }

    return false;
}

int send_ping_request(struct IP_Port ipp, struct clientid_t *client_id)
{
    struct pingreq_t pk;
    int       rc;
    uint64_t  ping_id;

    if (is_pinging(ipp, 0) || id_eq(client_id, self_id))
        return 1;

    // Generate random ping_id
    ping_id = add_ping(ipp);

    pk.magic = PACKET_PING_REQ;
    id_cpy(&pk.client_id, self_id);     // Our pubkey
    random_nonce((uint8_t *) &pk.nonce); // Generate random nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data((uint8_t *) client_id,
                      self_secret_key,
                      (uint8_t *) &pk.nonce,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      (uint8_t *) &pk.ping_id);

    if (rc != sizeof(ping_id) + ENCRYPTION_PADDING)
        return 1;

    return sendpacket(ipp, (uint8_t *) &pk, sizeof(pk));
}

int send_ping_response(struct IP_Port ipp, struct clientid_t *client_id, uint64_t ping_id)
{
    struct pingres_t pk;
    int       rc;

    if (id_eq(client_id, self_id))
        return 1;

    pk.magic = PACKET_PING_RES;
    id_cpy(&pk.client_id, self_id);     // Our pubkey
    random_nonce((uint8_t *) &pk.nonce); // Generate random nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data((uint8_t *) client_id,
                      self_secret_key,
                      (uint8_t *) &pk.nonce,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      (uint8_t *) &pk.ping_id);

    if (rc != sizeof(ping_id) + ENCRYPTION_PADDING)
        return 1;

    return sendpacket(ipp, (uint8_t *) &pk, sizeof(pk));
}

int handle_ping_request(struct IP_Port source, uint8_t *packet, uint32_t length)
{
    struct pingreq_t *p = (struct pingreq_t *) packet;
    int        rc;
    uint64_t   ping_id;

    if (length != sizeof(struct pingreq_t) || id_eq(&p->client_id, self_id))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data((uint8_t *) &p->client_id,
                      self_secret_key,
                      (uint8_t *) &p->nonce,
                      (uint8_t *) &p->ping_id,
                      sizeof(ping_id) + ENCRYPTION_PADDING,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    // Send response
    send_ping_response(source, &p->client_id, ping_id);
    add_toping((uint8_t *) &p->client_id, source);

    return 0;
}

int handle_ping_response(struct IP_Port source, uint8_t *packet, uint32_t length)
{
    struct pingres_t *p = (struct pingres_t *) packet;
    int       rc;
    uint64_t  ping_id;

    if (length != sizeof(struct pingres_t) || id_eq(&p->client_id, self_id))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data((uint8_t *) &p->client_id,
                      self_secret_key,
                      (uint8_t *) &p->nonce,
                      (uint8_t *) &p->ping_id,
                      sizeof(ping_id) + ENCRYPTION_PADDING,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    // Make sure ping_id is correct
    if (!is_pinging(source, ping_id))
        return 1;

    // Associate source ip with client_id
    addto_lists(source, (uint8_t *) &p->client_id);
    return 0;
}
