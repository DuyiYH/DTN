#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cla/cla.h"
#include "cla/ltpP.h"
#include "cla/cla_contact_tx_task.h"


#include "cla/posix/cla_ltp_common.h"
//#include "cla/posix/cla_tcp_common.h"
//#include "cla/posix/cla_tcp_util.h"

#include "platform/hal_io.h"
#include "platform/hal_semaphore.h"
#include "platform/hal_task.h"

#include "ud3tn/common.h"
#include "ud3tn/result.h"
#include "ud3tn/router_task.h"

#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

enum ud3tn_result cla_ltp_config_init(
	struct cla_ltp_config *config,
	const struct bundle_agent_interface *bundle_agent_interface)
{
	if (cla_config_init(&config->base, bundle_agent_interface) != UD3TN_OK)
		return UD3TN_FAIL;

	LOG("DEBUG : Arrive the function -- cla_ltp_config_init");

	config->listen_task = NULL;
	config->mEngineID = -1;

	return UD3TN_OK;
}

enum ud3tn_result cla_ltp_single_config_init(
	struct cla_ltp_single_config *config,
	const struct bundle_agent_interface *bundle_agent_interface)
{
	if (cla_ltp_config_init(&config->base,
				bundle_agent_interface) != UD3TN_OK)
		return UD3TN_FAIL;

	config->link = NULL;
	config->num_active_contacts = 0;

	LOG("DEBUG : Arrive the function --  hal_semaphore_init_binary()");

	config->contact_activity_sem = hal_semaphore_init_binary();
	if (!config->contact_activity_sem) {
		LOG("ltp: Cannot allocate memory for contact act. semaphore!");
		return UD3TN_FAIL;
	}

	return UD3TN_OK;
}

//undo
enum ud3tn_result cla_ltp_link_init(
	struct cla_ltp_link *link, int engineID,
	struct cla_ltp_config *config)
{
	ASSERT(engineID >= 0);
	link->connection_mEngineID = engineID;

	// This will fire up the RX and TX tasks
	if (cla_link_init(&link->base, &config->base) != UD3TN_OK)
		return UD3TN_FAIL;

	LOG("DEBUG : CLA link init success");

	return UD3TN_OK;
}

//undo
//此处的getNotice也需要判断类型，同时需要将得到的字符串复制给buffer
//此处需要死循环调用吗
enum ud3tn_result cla_ltp_read(struct cla_link *link,
			       uint8_t *buffer, size_t length,
			       size_t *bytes_read)
{	
	LOG("DEBUG : Arrive function -- cla_ltp_read");

	Notice ret = getNotice();

	if (ret.noticeType == 3) {
		buffer = (uint8_t *)ret.data.dataPoint;
		// 对接受类型的一个讨论应该在此处还是放到prase里面？
	} else {
		LOG("ltp: Error reading from getNotice");
		link->config->vtable->cla_disconnect_handler(link);
		return UD3TN_FAIL;
	}

	if (bytes_read)
		*bytes_read = ret.data.length;
	return UD3TN_OK;
}

// enum ud3tn_result cla_ltp_read(struct cla_link *link,
// 			       uint8_t *buffer, size_t length,
// 			       size_t *bytes_read)
// {	
// 	LOG("DEBUG : Arrive function -- cla_ltp_read");

// 	struct sockaddr_in cliaddr;
//     int len = sizeof(cliaddr);

// 	int num = recvfrom(serverFd, buffer, sizeof(buffer), 0, (struct sockaddr *)&cliaddr, &len);
	
// 	if (num < 0) {
// 		LOG("LTP: Error reading from socket:");
// 		link->config->vtable->cla_disconnect_handler(link);
// 		return UD3TN_FAIL;
// 	} else if (num == 0) {
// 		LOGF("LTP: A peer (via CLA %s) has disconnected gracefully!",
// 		     link->config->vtable->cla_name_get());
// 		link->config->vtable->cla_disconnect_handler(link);
// 		return UD3TN_FAIL;
// 	}

// 	if (bytes_read)
// 		*bytes_read = num;
// 	return UD3TN_OK;
// }

//undo
//tcp中的creat_socket返回的套接字应该等价于ltp中的sessionID,
//那么应该用transmissionMessage来获取？
//ltp无连接的话这边应该也不用了吧？							12/14
//此处需要设置对端连接，用ltp提供的setRemoteEID				12/16
enum ud3tn_result cla_ltp_connect(struct cla_ltp_config *const config,
				  const char *engineID)
{	
	/* 此处应该不需要，无连接？
	if (engineID == NULL)
		return UD3TN_FAIL;

	uvast destLTPEngineID = atoi(engineID);
	uaddr* uaddrToSend = {"test", 4};
	LtpSessionId tSessionID = transmissionRequest(1, destLTPEngineID, uaddrToSend, 4);

	//config->mEngineID = destLTPEngineID;
	config->mSessionID = tSessionID.sessionNbr;

	
	// unordered_map<int, int> sToEngineID_htab;
	// 如果本来有相应的config->mSessionID， 应该是
	// 此处存不存在边界条件？
	// if (sToEngineID_htab.find[config->mSessionID] != -1) {
	// 	continue;
	// }
	// sToEngineID_htab[config->mSessionID] = destLTPEngineID;
	

	LOGF(
		"LTP: CLA %s is now connected to [%s]",
		config->base.vtable->cla_name_get(),
		engineID
	);
	*/
	if (engineID == NULL)
		return UD3TN_FAIL;
	
	config->mEngineID = atoi(engineID);

	uvast remoteEngineID = (unsigned long long) config->mEngineID;

	addRemoteEngine(remoteEngineID);

	LOGF("DEBUG : Now we add connect to ltp:[%s].", engineID);

	for(int i = 0; i < 9; ++i) {
		if (i == 1) {
			RemoteInfoSet(remoteEngineID, i, remoteEngineID);
		}
		else {
			RemoteInfoSet(remoteEngineID, i , 1000);
		}
	}


	LOGF(
		"LTP: CLA %s is now connected to [%s]",
		config->base.vtable->cla_name_get(),
		engineID
	);

	return UD3TN_OK;
}

//这里的listen在ltp中应该不需要实现？应该是开启一个实例的同时就开始监听？
//此处的listen与后面的read_from_socket有什么区别，按理说ltp中不需要listen？直接在accept的时候调用getNotice并对消息进行处理
//undo
enum ud3tn_result cla_ltp_listen(struct cla_ltp_config *config,
				 const char *engineID,
				 int backlog)
{
	if (engineID == NULL)
		return UD3TN_FAIL;

	config->mEngineID = atoi(engineID);

	uvast localEngineID = (unsigned long long) config->mEngineID;
	
	for(int i = 0; i < 9; ++i) {
		if (i == 0) {
			localInfoSet(i, localEngineID);
		}
		else {
			localInfoSet(i, 1000);
		}
	}

	LOGF(
		"LTP: CLA %s is now listening on [%s]",
		config->base.vtable->cla_name_get(),
		engineID
	);

	return UD3TN_OK;
}

void cla_ltp_disconnect_handler(struct cla_link *link)
{
	struct cla_ltp_link *ltp_link = (struct cla_ltp_link *)link;

	//remove link中的engineID
	deleteRemoteEngine(ltp_link->connection_mEngineID);
	cla_generic_disconnect_handler(link);
}

void cla_ltp_single_disconnect_handler(struct cla_link *link)
{
	struct cla_ltp_single_config *ltp_config
		= (struct cla_ltp_single_config *)link->config;

	cla_ltp_disconnect_handler(link);
	ltp_config->link = NULL;
}

//无连接用不上
//sessionID需要进行维护
//暂不处理，作无效函数
//需要维护，setRemoteInfo应该在此做？ 但是此函数也负责listen
static void handle_established_connection(
	struct cla_ltp_single_config *config,
	int engineID, const size_t struct_size)
{
	ASSERT(struct_size >= sizeof(struct cla_ltp_link));
	struct cla_ltp_link *link = malloc(struct_size);

	ASSERT(!config->link);
	config->link = link;

	if (cla_ltp_link_init(link, engineID, &config->base) != UD3TN_OK) {
		LOG("LTP: Error creating a link instance!");
	} else {
		// Notify the router task of the newly established connection...
		struct router_signal rt_signal = {
			.type = ROUTER_SIGNAL_NEW_LINK_ESTABLISHED,
			.data = NULL,
		};
		const struct bundle_agent_interface *const bai =
			config->base.base.bundle_agent_interface;

		hal_queue_push_to_back(bai->router_signaling_queue, &rt_signal);

		cla_link_wait_cleanup(&link->base);

		LOG("DEBUG : Finish function -- handle_established_connection");
	}
	config->link = NULL;
	free(link);
}

//此处的single代表什么？ 绑定的是本地的IP:PORT还是对端的？（应该是都有？）
//single代表单个连接。
//single代表单个ltp类型的cla	绑定的IP：Port就是本地的
void cla_ltp_single_connect_task(struct cla_ltp_single_config *config,
				 const size_t struct_size)
{
	for (;;) {
		LOGF("LTP: CLA \"%s\": Attempting to connect to \"%s\".",
		     config->base.base.vtable->cla_name_get(),
		     config->engineID);

		if (cla_ltp_connect(&config->base,
				    config->engineID) != UD3TN_OK) {
			LOGF("LTP: CLA \"%s\": Connection failed, will retry in %d ms as long as a contact is ongoing.",
			     config->base.base.vtable->cla_name_get(),
			     CLA_TCP_RETRY_INTERVAL_MS);
			hal_task_delay(CLA_TCP_RETRY_INTERVAL_MS);
		} else {
			handle_established_connection(config,
							  config->base.mEngineID,
						      struct_size);
			LOGF("LTP: CLA \"%s\": Connection terminated, will reconnect as soon as a contact occurs.",
			     config->base.base.vtable->cla_name_get());
		}

		// Wait until _some_ contact starts.
		hal_semaphore_take_blocking(config->contact_activity_sem);
		hal_semaphore_release(config->contact_activity_sem);
	}
}
//undo
//明确：此处在accept本节点listen_socket的连接，因此需循环调用，并对每个接进来link进行处理
//此处应该是开启后就在监听？不需要BP手动调用？
//循环中对应accept_from_socket的作用应该是接收一个sessionID的功能，用来处理连接问题？
//首先不能用engineID代替sessionID， listen的时候会有多个对端连接，这个sessionID也许应该进行一个存储，置入ltp_link中，然后由ltp_link来进行维护
//所以应该不断调用getNotice，当返回的是一个没有接收过的sessionID，则进行存储，然后调用handle_established_connection？
//getNotice的情况太多，应当只对有消息进来的时候进行处理？但是会不会漏别的信息
void cla_ltp_single_listen_task(struct cla_ltp_single_config *config,
				const size_t struct_size)
{
	for (;;) {
		
		LOG("DEBUG : Start the func -- cla_ltp_single_listen_task, and use --getNotice");

		Notice ret = getNotice();

		if (ret.noticeType != 1) {
			LOG("ltp: No Ltp Transmission Session Start, ignore it.");
			continue;
		} 

		LtpSessionId tSID = ret.sessionID;

		unsigned int tSessionID = tSID.sessionNbr;
		uvast tEngineID = tSID.sourceEngineId;

		/*
		unordered_map<int, int> sToEngineID_htab;
		if (map.find(tSessionID) != -1) {
			continue;
		}
		map[tSessionID] = tEngineID;
		handle_established_connection(config, tSessionID, struct_size);
		按照此实现替换为C
		*/
		// LOG("DEBUG : At func -- cla_ltp_single_listen_task, have got //getNotice");

		// int engineId = atoi(config->engineID);
		handle_established_connection(config, tEngineID, struct_size);

		LOGF("LTP: CLA \"%s\" is looking for a new connection now!",
		     config->base.base.vtable->cla_name_get());
	}

	LOG("LTP: Connection broke, terminating listener.");
	ASSERT(0);
}

void cla_ltp_single_link_creation_task(struct cla_ltp_single_config *config,
				       const size_t struct_size)
{
	if (config->ltp_active) {
		cla_ltp_single_connect_task(config, struct_size);
		LOG("DEBUG : Arrive the function -- cla_ltp_single_connect_task, ltp is active");
	} else {
		if (cla_ltp_listen(&config->base,
				   config->engineID,
				   CLA_TCP_SINGLE_BACKLOG) != UD3TN_OK) {
			LOGF("LTP: CLA \"%s\" failed to bind to \"%s\".",
			     config->base.base.vtable->cla_name_get(),
			     config->engineID);
			ASSERT(0);
		}
		LOG("DEBUG : Arrive the function -- cla_ltp_single_listen_task");
		cla_ltp_single_listen_task(config, struct_size);
	}
}

struct cla_tx_queue cla_ltp_single_get_tx_queue(
	struct cla_config *config, const char *eid, const char *cla_addr)
{
	// For single-connection CLAs, these parameters are unused...
	(void)eid;
	(void)cla_addr;

	struct cla_ltp_link *const link =
		((struct cla_ltp_single_config *)config)->link;

	LOGF("DEBUG : Arrive the function: cla_ltp_single_get_tx_queue, eid is [%s], cla_addr is [%s]", eid, cla_addr);

	// No active link!
	if (!link) {
		LOG("DEBUG : The connection_mEngineID in link is none");
		return (struct cla_tx_queue){ NULL, NULL };
	}
		

	hal_semaphore_take_blocking(link->base.tx_queue_sem);

	// Freed while trying to obtain it
	if (!link->base.tx_queue_handle)
		return (struct cla_tx_queue){ NULL, NULL };

	LOG("DEBUG : Get ready to initialize the queue ");

	return (struct cla_tx_queue){
		.tx_queue_handle = link->base.tx_queue_handle,
		.tx_queue_sem = link->base.tx_queue_sem,
	};
}

enum ud3tn_result cla_ltp_single_start_scheduled_contact(
	struct cla_config *config, const char *eid, const char *cla_addr)
{
	struct cla_ltp_single_config *ltp_config
		= (struct cla_ltp_single_config *)config;

	// If we are the first contact (in parallel), start the connection!
	if (ltp_config->num_active_contacts == 0)
		hal_semaphore_release(ltp_config->contact_activity_sem);
	ltp_config->num_active_contacts++;

	// UNUSED
	(void)eid;
	(void)cla_addr;

	LOGF("DEBUG : Arrive the function -- cla_ltp_single_start_scheduled_contact, num_active_contacts = [%d]", ltp_config->num_active_contacts);

	return UD3TN_OK;
}

enum ud3tn_result cla_ltp_single_end_scheduled_contact(
	struct cla_config *config, const char *eid, const char *cla_addr)
{
	struct cla_ltp_single_config *ltp_config
		= (struct cla_ltp_single_config *)config;

	ltp_config->num_active_contacts--;
	// Block the link creation task from retrying.
	if (ltp_config->num_active_contacts == 0)
		hal_semaphore_take_blocking(ltp_config->contact_activity_sem);

	// UNUSED
	(void)eid;
	(void)cla_addr;

	return UD3TN_OK;
}


int cla_ltp_connect_to_cla_addr(const char *const cla_addr,
				const char *const default_service)
{
	ASSERT(cla_addr != NULL && cla_addr[0] != 0);

	int nEngineID = atoi(cla_addr);

	addRemoteEngine((uvast) nEngineID);

	return nEngineID;
}


//undo
//tcp返回的是数据长度
//ltp返回值呢
ssize_t ltp_send_all(unsigned int destClientServiceID, uvast destLTPengineID, 
	const void *data, const size_t length)
{
	LOGF("DEBUG : ltp_send start, data = [%s], destEngineID = [%d]", (char*)data, destLTPengineID);

	struct uaddr *dataBlock = {(char*)data, (unsigned int)length};

	//调用ltp提供的发送数据函数？
	struct LtpSessionId ltpSessionId = transmissionRequest(1, destLTPengineID, dataBlock, length);

	if(ltpSessionId.sessionNbr < 1 || ltpSessionId.sessionNbr > 16384) {
		return -1;
	}

	LOGF("DEBUG : ltp_send end, sourceEngineID = [%d], sessionNbr = [%d]", ltpSessionId.sourceEngineId, ltpSessionId.sessionNbr);

	return ltpSessionId.sessionNbr;
}

// ssize_t ltp_send_all(unsigned int destClientServiceID, uvast destLTPengineID, 
// 	const void *data, const size_t length)
// {

// 	int fd = socket(PF_INET, SOCK_DGRAM, 0);
    
//     if(fd == -1) {
//         perror("socket");
//         exit(-1);
//     }  

// 	struct sockaddr_in saddr;
//     saddr.sin_family = AF_INET;
//     saddr.sin_port = htons(9999);
//     inet_pton(AF_INET, "10.0.1.2", &saddr.sin_addr.s_addr);

// 	char* sendBuf = (char*)data;

// 	sendto(fd, sendBuf, strlen(sendBuf) + 1, 0, (struct sockaddr *)&saddr, sizeof(saddr));

// 	return 1;
// }

enum ud3tn_result parse_ltp_active(const char *str, bool *ltp_active)
{
	if (!strcmp(str, CLA_OPTION_LTP_ACTIVE))
		*ltp_active = true;
	else if (!strcmp(str, CLA_OPTION_LTP_PASSIVE))
		*ltp_active = false;
	else
		return UD3TN_FAIL;

	return UD3TN_OK;
}

//ltp_proto
void mltp_parser_reset(struct parser *mltp_parser)
{
	mltp_parser->status = PARSER_STATUS_GOOD;
	mltp_parser->next_bytes = 0;
	mltp_parser->flags = PARSER_FLAG_NONE;
}

size_t mltp_parser_parse(struct parser *mltp_parser,
			 const uint8_t *buffer,
			 size_t length)
{
	CborParser parser;
	CborValue it;
	CborError err;
	size_t pl_length = 0;

	err = cbor_parser_init(buffer, length, 0, &parser, &it);
	if (err == CborNoError && !cbor_value_is_byte_string(&it))
		err = CborErrorIllegalType;
	if (err == CborNoError)
		err = cbor_value_get_string_length(&it, &pl_length);
	if (err == CborErrorUnexpectedEOF) {
		// We need more data!
		return 0;
	} else if (err != CborNoError) {
		LOG("mtcp: Invalid CBOR byte string header provided.");
		// Skip 1 byte
		return 1;
	}

	mltp_parser->flags = PARSER_FLAG_DATA_SUBPARSER;
	mltp_parser->next_bytes = pl_length;

	// See block_data(...) in the bundle7 parser for a detailed
	// explanation of what happens here.
	it.type = CborIntegerType;
	// NOTE: Intentionally no error handling, see bundle7 parser!
	cbor_value_advance_fixed(&it);

	return cbor_value_get_next_byte(&it) - buffer;
}

size_t mltp_encode_header(uint8_t *const buffer, const size_t buffer_size,
			  const size_t data_length)
{
	CborEncoder encoder;

	ASSERT(buffer_size >= 9);
	cbor_encoder_init(&encoder, buffer, buffer_size, 0);
	ASSERT(cbor_encode_uint(&encoder, data_length) == CborNoError);

	const size_t hdr_len = cbor_encoder_get_buffer_size(&encoder, buffer);

	ASSERT(hdr_len != 0);
	buffer[0] |= 0x40; // CBOR uint -> byte string

	return hdr_len;
}
