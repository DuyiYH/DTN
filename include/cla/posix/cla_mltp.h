#ifndef CLA_MLTP_H
#define CLA_MLTP_H

#include "cla/cla.h"
#include "cla/ltpP.h"

#include "cla/posix/cla_ltp_common.h"
#include "cla/posix/cla_tcp_common.h"

#include "ud3tn/bundle_agent_interface.h"
#include "ud3tn/result.h"


#include "platform/hal_types.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <sys/socket.h>

struct cla_config *mltp_create(
	const char *const options[], const size_t option_count,
	const struct bundle_agent_interface *bundle_agent_interface);

struct mltp_link {
	struct cla_ltp_link base;
	struct parser mltp_parser;
};

size_t mltp_mbs_get(struct cla_config *const config);

void mltp_reset_parsers(struct cla_link *link);

size_t mltp_forward_to_specific_parser(struct cla_link *link,
				       const uint8_t *buffer, size_t length);

void mltp_begin_packet(struct cla_link *link, size_t length);

void mltp_end_packet(struct cla_link *link);

void mltp_send_packet_data(
	struct cla_link *link, const void *data, const size_t length);

/* add for test */
void ltp_config(int engineId);
void ltp_send(int sessionId, char* data, size_t length);
void ltp_recv(int sessionId, int fd);

#endif /* CLA_MLTP_H */
