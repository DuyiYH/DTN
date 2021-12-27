#include "cla/cla.h"
#include "cla/ltpP.h"
#include "cla/cla_contact_tx_task.h"
#include "cla/mtcp_proto.h"
#include "cla/posix/cla_mltp.h"
#include "cla/posix/cla_mtcp.h"
#include "cla/posix/cla_smtcp.h"
#include "cla/posix/cla_ltp_common.h"
//#include "cla/posix/cla_tcp_common.h"
//#include "cla/posix/cla_tcp_util.h"

#include "bundle6/parser.h"
#include "bundle7/parser.h"

// #include "ltpP.h"

#include "platform/hal_config.h"
#include "platform/hal_io.h"
#include "platform/hal_semaphore.h"
#include "platform/hal_task.h"
#include "platform/hal_types.h"

#include "ud3tn/bundle_agent_interface.h"
#include "ud3tn/cmdline.h"
#include "ud3tn/common.h"
#include "ud3tn/config.h"
#include "ud3tn/result.h"
#include "ud3tn/simplehtab.h"
#include "ud3tn/task_tags.h"

#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// int serverFd;

struct mltp_config {
	struct cla_ltp_config base;

	struct htab_entrylist *param_htab_elem[CLA_LTP_PARAM_HTAB_SLOT_COUNT];
	struct htab param_htab;
	Semaphore_t param_htab_sem;
};

struct mltp_contact_parameters {
	// IMPORTANT: The cla_tcp_link is only initialized iff connected == true
	struct mltp_link link;

	struct mltp_config *config;

	Task_t management_task;

	char *cla_addr;

	bool in_contact;
	bool connected;
	int connect_attempt;

	int engineID;
};

static void mltp_link_creation_task(void *param)
{
	struct cla_ltp_single_config *const mltp_config = param;

	LOGF("mltp: Using %s mode",
	     mltp_config->ltp_active ? "active" : "passive");
	cla_ltp_single_link_creation_task(
		mltp_config,
		sizeof(struct mltp_link)
	);
	ASSERT(0);
}

static enum ud3tn_result handle_established_connection(
	struct mltp_contact_parameters *const param)
{
	struct mltp_config *const mltp_config = param->config;

	if (cla_ltp_link_init(&param->link.base, param->engineID,
			      &mltp_config->base)!= UD3TN_OK) {
		LOG("MLTP: Error initializing CLA link!");
		return UD3TN_FAIL;
	}

	cla_link_wait_cleanup(&param->link.base.base);

	return UD3TN_OK;
}

//此处关于socket小于0的判断在ltp中不需要，但是怎么修改还需要再看
static void mltp_link_management_task(void *p)
{
	struct mltp_contact_parameters *const param = p;

	LOGF("DEBUG : cla_addr = [%s], func -- mtcp_link_management_task", param->cla_addr);
	ASSERT(param->cla_addr != NULL);
	do {
		if (param->connected) {
			ASSERT(param->engineID > 0);
			handle_established_connection(param);
			param->connected = false;
			param->connect_attempt = 0;
			param->engineID = -1;
		} else {
			ASSERT(param->engineID < 0);
			param->engineID = cla_ltp_connect_to_cla_addr(
				param->cla_addr,
				NULL
			);
			if (param->engineID < 0) {
				if (++param->connect_attempt >
						CLA_LTP_MAX_RETRY_ATTEMPTS) {
					LOG("MLTP: Final retry failed.");
					break;
				}
				LOGF("MLTP: Delayed retry %d of %d in %d ms",
				     param->connect_attempt,
				     CLA_LTP_MAX_RETRY_ATTEMPTS,
				     CLA_LTP_RETRY_INTERVAL_MS);
				hal_task_delay(CLA_LTP_RETRY_INTERVAL_MS);
				continue;
			}
			//此处应当调用setRemoteEngineID
			LOGF("MLTP: Connected successfully to \"%s\"",
			     param->cla_addr);
			param->connected = true;
		}
	} while (param->in_contact);
	LOGF("MLTP: Terminating contact link manager for \"%s\"",
	     param->cla_addr);
	hal_semaphore_take_blocking(param->config->param_htab_sem);
	htab_remove(&param->config->param_htab, param->cla_addr);
	hal_semaphore_release(param->config->param_htab_sem);
	mltp_parser_reset(&param->link.mltp_parser);
	free(param->cla_addr);

	Task_t management_task = param->management_task;

	free(param);
	hal_task_delete(management_task);
}

static void launch_connection_management_task(
	struct mltp_config *const mltp_config,
	const int engineID, const char *cla_addr)
{
	LOGF("DEBUG1 : cla_addr is [%s], func -- launch_connection_management_task", cla_addr);

	ASSERT(cla_addr);

	LOGF("DEBUG2 : cla_addr is [%s], func -- launch_connection_management_task", cla_addr);

	struct mltp_contact_parameters *contact_params =
		malloc(sizeof(struct mltp_contact_parameters));

	if (!contact_params) {
		LOG("MLTP: Failed to allocate memory!");
		return;
	}

	contact_params->config = mltp_config;
	contact_params->connect_attempt = 0;

	if (engineID < 0) {
		contact_params->cla_addr = cla_get_connect_addr(
			cla_addr,
			"mltp"
		);
		LOGF("DEBUG1 : contact_params->cla_addr = [%s], func --launch_connection_management_task", contact_params->cla_addr);
		contact_params->engineID = -1;
		contact_params->connected = false;
		contact_params->in_contact = true;
	} else {
		ASSERT(engineID != -1);
		contact_params->cla_addr = strdup(cla_addr);
		LOGF("DEBUG2 : cla_addr = [%s], func -- launch_connection_management_task", contact_params->cla_addr);
		contact_params->engineID = engineID;
		contact_params->connected = true;
		contact_params->in_contact = false;
	}

	if (!contact_params->cla_addr) {
		LOG("MLTP: Failed to copy CLA address!");
		goto fail;
	}

	mltp_parser_reset(&contact_params->link.mltp_parser);

	struct htab_entrylist *htab_entry = NULL;

	htab_entry = htab_add(
		&mltp_config->param_htab,
		contact_params->cla_addr,
		contact_params
	);
	if (!htab_entry) {
		LOG("MLTP: Error creating htab entry!");
		goto fail;
	}

	contact_params->management_task = hal_task_create(
		mltp_link_management_task,
		"mltp_mgmt_t",
		CONTACT_MANAGEMENT_TASK_PRIORITY,
		contact_params,
		CONTACT_MANAGEMENT_TASK_STACK_SIZE,
		(void *)CLA_SPECIFIC_TASK_TAG
	);

	if (!contact_params->management_task) {
		LOG("MLTP: Error creating management task!");
		if (htab_entry) {
			ASSERT(contact_params->cla_addr);
			ASSERT(htab_remove(
				&mltp_config->param_htab,
				contact_params->cla_addr
			) == contact_params);
		}
		goto fail;
	}

	return;

fail:
	free(contact_params->cla_addr);
	free(contact_params);
}

static void mltp_listener_task(void *param)
{
	struct mltp_config *const mltp_config = param;
	char *cla_addr;
	int engineID;

	LOGF("DEBUG : cla_ltp_config->mengineID = [%d]. func -- mltp_listener_task.", mltp_config->base.mEngineID);

	for (;;) {

		LOG("DEBUG : getNotice start");

		Notice ret = getNotice();

		LOGF("DEBUG : noticetype = [%d], func -- mltp_listener_task ", ret.noticeType);

		if (ret.noticeType != 1) {
			LOG("ltp: No Ltp Transmission Session Start, ignore it.");
			continue;
		} 

		LOG("DEBUG : after getNotice");

		LtpSessionId tSID = ret.sessionID;

		unsigned int tSessionID = tSID.sessionNbr;
		uvast tEngineID = tSID.sourceEngineId;
		engineID = tEngineID;

		// itoa(engineID, cla_addr, 10);
		sprintf(cla_addr, "%d", engineID);

		LOGF("DEBUG : cla_addr = [%s], engineID = [%d]. func -- mltp_listener_task", cla_addr, engineID);

		hal_semaphore_take_blocking(mltp_config->param_htab_sem);
		launch_connection_management_task(
			mltp_config,
			engineID,
			cla_addr
		);
		hal_semaphore_release(mltp_config->param_htab_sem);
		free(cla_addr);
		free(engineID);
	}
	// unexpected failure to accept() - exit thread in release mode
	ASSERT(0);
}

static enum ud3tn_result mltp_launch(struct cla_config *const config)
{
	struct mltp_config *const mltp_config = (struct mltp_config *)config;

	mltp_config->base.listen_task = hal_task_create(
		mltp_listener_task,
		"mltp_listen_t",
		CONTACT_LISTEN_TASK_PRIORITY,
		config,
		CONTACT_LISTEN_TASK_STACK_SIZE,
		(void *)CLA_SPECIFIC_TASK_TAG
	);

	if (!mltp_config->base.listen_task)
		return UD3TN_FAIL;

	LOG("DEBUG : Accomplish the function -- mltp_launch");
	
	return UD3TN_OK;
}

static const char *mltp_name_get(void)
{
	return "mltp";
}



size_t mltp_mbs_get(struct cla_config *const config)
{
	(void)config;
	return SIZE_MAX;
}

void mltp_reset_parsers(struct cla_link *link)
{
	struct mltp_link *const mltp_link = (struct mltp_link *)link;

	rx_task_reset_parsers(&link->rx_task_data);

	mltp_parser_reset(&mltp_link->mltp_parser);
	link->rx_task_data.cur_parser = &mltp_link->mltp_parser;
}

size_t mltp_forward_to_specific_parser(struct cla_link *link,
				       const uint8_t *buffer, size_t length)
{
	struct mltp_link *const mltp_link = (struct mltp_link *)link;
	struct rx_task_data *const rx_data = &link->rx_task_data;
	size_t result = 0;

	// Decode MTCP CBOR byte string header if not done already
	if (!(mltp_link->mltp_parser.flags & PARSER_FLAG_DATA_SUBPARSER))
		return mltp_parser_parse(&mltp_link->mltp_parser,
					 buffer, length);

	// We do not allow to parse more than the stated length...
	if (length > mltp_link->mltp_parser.next_bytes)
		length = mltp_link->mltp_parser.next_bytes;

	switch (rx_data->payload_type) {
	case PAYLOAD_UNKNOWN:
		result = select_bundle_parser_version(rx_data, buffer, length);
		if (result == 0)
			mtcp_reset_parsers(link);
		break;
	case PAYLOAD_BUNDLE6:
		rx_data->cur_parser = rx_data->bundle6_parser.basedata;
		result = bundle6_parser_read(
			&rx_data->bundle6_parser,
			buffer,
			length
		);
		break;
	case PAYLOAD_BUNDLE7:
		rx_data->cur_parser = rx_data->bundle7_parser.basedata;
		result = bundle7_parser_read(
			&rx_data->bundle7_parser,
			buffer,
			length
		);
		break;
	default:
		mltp_reset_parsers(link);
		return 0;
	}

	ASSERT(result <= mltp_link->mltp_parser.next_bytes);
	mltp_link->mltp_parser.next_bytes -= result;

	// All done
	if (!mltp_link->mltp_parser.next_bytes)
		mltp_reset_parsers(link);

	return result;
}



/*
 * TX
 */

static struct mltp_contact_parameters *get_contact_parameters(
	struct cla_config *config, const char *cla_addr)
{
	struct mltp_config *const mltp_config =
		(struct mltp_config *)config;
	char *const cla_ltp_addr = cla_get_connect_addr(cla_addr, "mltp"); //IP地址类似于198.162.0.0  1001

	LOGF("DEBUG : cla_ltp_addr = [%s], func -- get_contact_parameters", cla_ltp_addr);

	struct mltp_contact_parameters *param = htab_get(
		&mltp_config->param_htab,
		cla_ltp_addr
	);
	free(cla_ltp_addr);
	LOGF("DEBUG : param = [%p], func -- get_contact_parameters", param);
	return param;
}

static struct cla_tx_queue mltp_get_tx_queue(
	struct cla_config *config, const char *eid, const char *cla_addr)
{
	(void)eid;
	struct mltp_config *const mltp_config = (struct mltp_config *)config;

	hal_semaphore_take_blocking(mltp_config->param_htab_sem);
	struct mltp_contact_parameters *const param = get_contact_parameters(
		config,
		cla_addr
	);

	if (param && param->connected) {
		struct cla_link *const cla_link = &param->link.base.base;

		hal_semaphore_take_blocking(cla_link->tx_queue_sem);
		hal_semaphore_release(mltp_config->param_htab_sem);

		// Freed while trying to obtain it
		if (!cla_link->tx_queue_handle)
			return (struct cla_tx_queue){ NULL, NULL };

		return (struct cla_tx_queue){
			.tx_queue_handle = cla_link->tx_queue_handle,
			.tx_queue_sem = cla_link->tx_queue_sem,
		};
	}

	hal_semaphore_release(mltp_config->param_htab_sem);
	return (struct cla_tx_queue){ NULL, NULL };
}

static enum ud3tn_result mltp_start_scheduled_contact(
	struct cla_config *config, const char *eid, const char *cla_addr)
{
	(void)eid;
	LOGF("DEBUG : eid = [%s], cla_addr = [%s], func -- mltp_start_scheduled_contact, start", eid, cla_addr);
	struct mltp_config *const mltp_config = (struct mltp_config *)config;
	LOG("DEBUG : func -- mltp_start_scheduled_contact, 2");
	hal_semaphore_take_blocking(mltp_config->param_htab_sem);
	struct mltp_contact_parameters *const param = get_contact_parameters(
		config,
		cla_addr
	);

	if (param) {
		LOGF("MLTP: Associating open connection with \"%s\" to new contact",
		     cla_addr);
		param->in_contact = true;
		LOG("DEBUG : func -- mltp_start_scheduled_contact, 4");
		hal_semaphore_release(mltp_config->param_htab_sem);
		return UD3TN_OK;
	}
	launch_connection_management_task(mltp_config, -1, cla_addr);


	hal_semaphore_release(mltp_config->param_htab_sem);
	return UD3TN_OK;
}

static enum ud3tn_result mltp_end_scheduled_contact(
	struct cla_config *config, const char *eid, const char *cla_addr)
{
	(void)eid;
	struct mltp_config *const mltp_config = (struct mltp_config *)config;

	hal_semaphore_take_blocking(mltp_config->param_htab_sem);
	struct mltp_contact_parameters *const param = get_contact_parameters(
		config,
		cla_addr
	);

	if (param && param->in_contact) {
		LOGF("MLTP: Marking open connection with \"%s\" as opportunistic",
		     cla_addr);
		param->in_contact = false;
		if (CLA_MLTP_CLOSE_AFTER_CONTACT && param->engineID >= 0) {
			LOGF("MLTP: Terminating connection with \"%s\"",
			     cla_addr);
			//close(param->engineID);
			deleteRemoteEngine(param->engineID);
		}
	}

	hal_semaphore_release(mltp_config->param_htab_sem);

	return UD3TN_OK;
}

//在tcp中该函数作用：测试该连接是主动发出或是被动接收，如果该连接是主动连接，则尝试编码发送看是否成功；不成功则处理该连接
void mltp_begin_packet(struct cla_link *link, size_t length)
{
	struct cla_ltp_link *const ltp_link = (struct cla_ltp_link *)link;

	// A previous operation may have canceled the sending process.
	if (!link->active)
		return;

	const size_t BUFFER_SIZE = 9; // max. for uint64_t
	uint8_t buffer[BUFFER_SIZE];

	const size_t hdr_len = mltp_encode_header(buffer, BUFFER_SIZE, length);

	//将char数组转为void*
	void* data = &buffer;

	//此时ltp_link中的sessionID已经有了，如果向同一个engineID发送的话会再生成另一个sessionID
	if (ltp_send_all(1, ltp_link->connection_mEngineID, data, hdr_len) == 0) {
		LOG("mtcp: Error during sending. Data discarded.");
		link->config->vtable->cla_disconnect_handler(link);
	}
}

void mltp_end_packet(struct cla_link *link)
{
	// STUB
	(void)link;
}

void mltp_send_packet_data(
	struct cla_link *link, const void *data, const size_t length)
{
	struct cla_ltp_link *const ltp_link = (struct cla_ltp_link *)link;

	// A previous operation may have canceled the sending process.
	if (!link->active)
		return;
	

	if (ltp_send_all(1, ltp_link->connection_mEngineID, data, length) == -1) {
		LOG("mltp: Error during sending. Data discarded.");
		link->config->vtable->cla_disconnect_handler(link);
	}
}



const struct cla_vtable mltp_vtable = {
	.cla_name_get = mltp_name_get,
	.cla_launch = mltp_launch,

	.cla_mbs_get = mltp_mbs_get,

	.cla_get_tx_queue = mltp_get_tx_queue,
	.cla_start_scheduled_contact = mltp_start_scheduled_contact,
	.cla_end_scheduled_contact = mltp_end_scheduled_contact,

	.cla_begin_packet = mltp_begin_packet,
	.cla_end_packet = mltp_end_packet,
	.cla_send_packet_data = mltp_send_packet_data,

	.cla_rx_task_reset_parsers = mltp_reset_parsers,
	.cla_rx_task_forward_to_specific_parser =
		mltp_forward_to_specific_parser,

	.cla_read = cla_ltp_read,

	.cla_disconnect_handler = cla_ltp_disconnect_handler,
};

static enum ud3tn_result mltp_init(
	struct mltp_config *config,
	const char *engineID,
	const struct bundle_agent_interface *bundle_agent_interface)
{
	/* Initialize base_config */
	if (cla_ltp_config_init(&config->base,
				bundle_agent_interface) != UD3TN_OK)
		return UD3TN_FAIL;

	/* set base_config vtable */
	config->base.base.vtable = &mltp_vtable;

	LOG("DEBUG : Creat mltp_vtable successfully, maybe after mltp_launch");

	htab_init(&config->param_htab, CLA_LTP_PARAM_HTAB_SLOT_COUNT,
		  config->param_htab_elem);

	config->param_htab_sem = hal_semaphore_init_binary();
	hal_semaphore_release(config->param_htab_sem);

	/* Start listening */
	if (cla_ltp_listen(&config->base, engineID,
			   CLA_LTP_MULTI_BACKLOG) != UD3TN_OK)
		return UD3TN_FAIL;

	// serverFd = socket(PF_INET, SOCK_DGRAM, 0);

	// if(serverFd == -1) {
    //     perror("socket");
    //     exit(-1);
    // } 

	// struct sockaddr_in addr;
    // addr.sin_family = AF_INET;
    // addr.sin_port = htons(9999);
    // addr.sin_addr.s_addr = INADDR_ANY;

	// int ret = bind(serverFd, (struct sockaddr *)&addr, sizeof(addr));
    // if(ret == -1) {
    //     perror("bind");
    //     exit(-1);
    // }

	return UD3TN_OK;
}

struct cla_config *mltp_create(
	const char *const options[], const size_t option_count,
	const struct bundle_agent_interface *bundle_agent_interface)
{
	if (option_count != 1) {
		LOG("mltp: Options format has to be: <ENGINEID>");
		return NULL;
	}

	struct mltp_config *config = malloc(sizeof(struct mltp_config));

	if (!config) {
		LOG("mltp: Memory allocation failed!");
		return NULL;
	}

	LOGF("DEBUG : options[0] = [%s]. func -- mltp_creat", options[0]);

	if (mltp_init(config, options[0],bundle_agent_interface) != UD3TN_OK) {
		free(config);
		LOG("mltp: Initialization failed!");
		return NULL;
	}

	return &config->base.base;
}
