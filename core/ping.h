/*
 * ping.h -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <stdbool.h>

void init_ping();
uint64_t add_ping(struct IP_Port ipp);
bool is_pinging(struct IP_Port ipp, uint64_t ping_id);
int send_ping_request(struct IP_Port ipp, clientid_t *client_id);
int send_ping_response(struct IP_Port ipp, clientid_t *client_id, uint64_t ping_id);
int handle_ping_request(struct IP_Port source, uint8_t *packet, uint32_t length);
int handle_ping_response(struct IP_Port source, uint8_t *packet, uint32_t length);
