#ifndef CLA_MLTP_H
#define CLA_MLTP_H

#include "cla/cla.h"

#include "ud3tn/bundle_agent_interface.h"

#include <stddef.h>

struct cla_config *mltp_create(
	const char *const options[], const size_t option_count,
	const struct bundle_agent_interface *bundle_agent_interface);

/* add for test */
int ltp_send(int a, int b);
int ltp_recv(int a, int b);

#endif /* CLA_MLTP_H */
