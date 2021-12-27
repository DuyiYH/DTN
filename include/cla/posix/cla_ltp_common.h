#ifndef CLA_LTP_COMMON_H_INCLUDED
#define CLA_LTP_COMMON_H_INCLUDED

#include "cla/cla.h"
#include "cla/ltpP.h"

#include "ud3tn/bundle_agent_interface.h"
#include "ud3tn/parser.h"
#include "ud3tn/result.h"
#include "ud3tn/simplehtab.h"

#include "platform/hal_types.h"


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <netinet/in.h>
#include <sys/socket.h>

#define CLA_OPTION_LTP_ACTIVE "true"
#define CLA_OPTION_LTP_PASSIVE "false"

//undo
//此处不需要engineID?
struct cla_ltp_link {
	struct cla_link base;
	//struct parser ltp_parser;

	//int sessionID;
	/*此处待商榷*/
	int connection_mEngineID;
};

//undo
//此处的mEngineID不对吧，其在cla_tcp_connect中进行复制，是连接对端engineID的一个文件描述符，应用sessionID替换
struct cla_ltp_config {
	struct cla_config base;

	//int mSessionID;
	int mEngineID;

	/* Task handle for the listener - required to support concurrent CLAs */
	Task_t listen_task;
};

//此hashtable以sessionID为key，engineID为value？
// static const struct sToEngineID_htab {
// 	struct htab_entrylist *sToE_htab_elem[CLA_TCP_PARAM_HTAB_SLOT_COUNT];
// 	struct htab sToE_htab;
// }

struct cla_ltp_single_config {
	struct cla_ltp_config base;

	/* The active link, if there is any, else NULL */
	struct cla_ltp_link *link;

	/* Whether or not to connect (pro)actively. If false, listen. */
	bool ltp_active;

	/* The number of contacts currently handled via this CLA. */
	int num_active_contacts;

	/* Semaphore for waiting until (some) contact is active. */
	Semaphore_t contact_activity_sem;

	/* The engineID to bind/connect to. */
	const char *engineID;
};

/*
 * Private API
 */

enum ud3tn_result cla_ltp_config_init(
	struct cla_ltp_config *config,
	const struct bundle_agent_interface *bundle_agent_interface);

enum ud3tn_result cla_ltp_single_config_init(
	struct cla_ltp_single_config *config,
	const struct bundle_agent_interface *bundle_agent_interface);

enum ud3tn_result cla_ltp_single_link_init(
	struct cla_link *link,
	struct cla_ltp_config *config);

enum ud3tn_result cla_ltp_link_init(
	struct cla_ltp_link *link, int connected_engineID,
	struct cla_ltp_config *config);

enum ud3tn_result cla_ltp_listen(struct cla_ltp_config *config,
				 const char *engineID,
				 int backlog);

//undo
//此函数是否需要？
int cla_ltp_accept_from_socket(struct cla_ltp_config *config,
			       int listener_socket,
			       char **addr);

enum ud3tn_result cla_ltp_connect(struct cla_ltp_config *config,
				  const char *engineID);

void cla_ltp__single_connect_task(struct cla_ltp_config *config,
				 const size_t struct_size);

void cla_ltp_single_listen_task(struct cla_ltp_single_config *config,
				const size_t struct_size);

void cla_ltp_single_link_creation_task(struct cla_ltp_single_config *config,
				       const size_t struct_size);

ssize_t ltp_send_all(unsigned int destClientServiceID, uvast destLTPengineID, 
	const void *data, const size_t length);
// For the config vtable...

struct cla_tx_queue cla_ltp_single_get_tx_queue(
	struct cla_config *config, const char *eid, const char *cla_addr);

enum ud3tn_result cla_ltp_single_start_scheduled_contact(
	struct cla_config *config, const char *eid, const char *cla_addr);

enum ud3tn_result cla_ltp_single_end_scheduled_contact(
	struct cla_config *config, const char *eid, const char *cla_addr);

void cla_ltp_disconnect_handler(struct cla_link *link);

void cla_ltp_single_disconnect_handler(struct cla_link *link);

/**
 * Create a new TCP socket and connect to the specified CLA address.
 *
 * @param cla_addr The CLA address, i.e. a combination of node and service name.
 * @param default_service The default service (port), if nothing is specified.
 * @return A TCP socket, or -1 on error.
 */
int cla_ltp_connect_to_cla_addr(const char *const cla_addr,
				const char *const default_service);


/**
 * @brief Read at most "length" bytes from the interface into a buffer.
 *
 * The user must assert that the current buffer is large enough to contain
 * "length" bytes.
 *
 * @param buffer The target buffer to be read to.
 * @param length Size of the buffer in bytes.
 * @param bytes_read Number of bytes read into the buffer.
 * @return Specifies if the read was successful.
 */
enum ud3tn_result cla_ltp_read(struct cla_link *link,
			       uint8_t *buffer, size_t length,
			       size_t *bytes_read);

/**
 * @brief Parse the "ltp active" command line option.
 *
 * @param str The command line option string.
 * @param ltp_active Returns the "ltp active" flag.
 * @return A value indicating whether the operation was successful.
 */
enum ud3tn_result parse_ltp_active(const char *str, bool *ltp_active);


void mltp_parser_reset(struct parser *mltp_parser);

size_t mltp_parser_parse(struct parser *mltp_parser,
			 const uint8_t *buffer,
			 size_t length);

size_t mltp_encode_header(uint8_t *buffer, size_t buffer_size,
			  size_t data_length);


#endif // CLA_LTP_COMMON_H_INCLUDED
