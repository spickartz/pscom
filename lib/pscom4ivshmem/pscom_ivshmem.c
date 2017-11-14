/*
 * Original Work
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:      Jens Hauke <hauke@par-tec.com>
 */

/*
 * Modified work
 * Author:      Jonas Baude <jonas.baude@rwth-aachen.de>
 *
 */


#include "psivshmem.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <malloc.h>

#include "pscom_con.h"
#include "pscom_io.h"
#include "pscom_ivshmem.h"
#include "pscom_precon.h"
#include "pscom_priv.h"
#include "pscom_req.h"
#include "pscom_util.h"
#include "psivshmem.h"

#if defined(__x86_64__) && !(defined(__KNC__) || defined(__MIC__))
/* We need memory barriers only for x86_64 (?) */
#define ivshmem_mb()    asm volatile("mfence":::"memory")
#elif defined(__ia64__)
#define ivshmem_mb()    asm volatile ("mf" ::: "memory")
#else
/* Dont need it for ia32, alpha (?) */
#define ivshmem_mb()    asm volatile ("" :::"memory")
#endif

/*################################################################################################*/

int ivshmem_init_state = 1;
ivshmem_pci_dev_t pscom_ivshmem_device_handle;
static unsigned ivshmem_direct = 400;

static
struct {
	struct pscom_poll_reader poll_reader; // calling shm_poll_pending_io(). Used if !list_empty(shm_conn_head)
	struct list_head ivshmem_conn_head; // shm_conn_t.pending_io_next_conn.
} ivshmem_pending_io;


struct ivshmem_direct_header {
	void	*base;
	size_t	len;
};


static
int pscom_ivshmem_initrecv(ivshmem_conn_t *ivshmem)
{
	void *buf;

	buf = psivshmem_alloc_mem(ivshmem->device, sizeof(psivshmem_com_t)); //returns ptr to first byte or NULL on error

	if (!buf) goto error;
	memset(buf, 0, sizeof(psivshmem_com_t));  // init with zeros
	ivshmem->local_com = (psivshmem_com_t*)buf;
	ivshmem->recv_cur = 0;

	return 0;

error:
	DPRINT(1, "ivshmem: psivshmem_alloc_mem unsuccessful...!");
	return -1;
}


static
int pscom_ivshmem_initsend(ivshmem_conn_t *ivshmem, void* rem_buf_offset)
{
	void *buf;

	buf = (void*)(ivshmem->device->ivshmem_base +(long)rem_buf_offset);  //mind: both have own virtual adress spaces ;-)
	if (!buf) goto error;

	ivshmem->remote_com = buf;
	ivshmem->send_cur = 0;
	return 0;

error:
	DPRINT(1, "ivshmem: Some trouble in pscom_ivshmem_initsend(...)!");
	return -1;
}


static
void pscom_ivshmem_init_direct(ivshmem_conn_t *ivshmem, long remote_offset, void *remote_base)
{
	if (remote_offset == 0) {
		ivshmem->direct_offset = 0;
		ivshmem->direct_base = NULL;
		return;
	}

	void *buf = (void*)((char*)ivshmem->device->ivshmem_base + remote_offset);// = shmat(ivshmemid, 0, IVSHMEM_RDONLY); ToDo
	assert(buf != (void *) -1 && buf);

	ivshmem->direct_base = buf; //remote_base;//buf;
	ivshmem->direct_offset = (char *)buf - (char*)remote_base;//remote_offset;//(char *)buf - (char *)remote_base;
}

static inline
uint32_t pscom_ivshmem_canrecv(ivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];
	return ivshmembuf->header.msg_type;
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_STD (no check inside)!
*/
static inline
void pscom_ivshmem_recvstart(ivshmem_conn_t *ivshmem, char **buf, unsigned int *len)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	*len = ivshmembuf->header.len;
	*buf = IVSHMEM_DATA(ivshmembuf, *len);
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_DIRECT (no check inside)!
*/
static inline
void pscom_ivshmem_recvstart_direct(ivshmem_conn_t *ivshmem, struct iovec iov[2])
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	unsigned len = ivshmembuf->header.len;
	char *data = IVSHMEM_DATA(ivshmembuf, len);

	iov[0].iov_base = data;
	iov[0].iov_len = len;

	struct ivshmem_direct_header *dh = (struct ivshmem_direct_header *)(data - sizeof(*dh));

	iov[1].iov_base = dh->base + ivshmem->direct_offset;
	iov[1].iov_len = dh->len;
}


static inline
void pscom_ivshmem_recvdone(ivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	ivshmem_mb();

	/* Notification: message is read */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_NONE;

	/* free buffer */
	ivshmem->recv_cur = (ivshmem->recv_cur + 1) % IVSHMEM_BUFS;
}


static inline
void pscom_ivshmem_recvdone_direct(ivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->recv_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->local_com->buf[cur];

	ivshmem_mb();

	/* Notification: message is read */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_DIRECT_DONE;

	/* free buffer */
	ivshmem->recv_cur = (ivshmem->recv_cur + 1) % IVSHMEM_BUFS;
}


static
int pscom_ivshmem_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	uint32_t ret;
	char *buf;
	unsigned int len;

	ret = pscom_ivshmem_canrecv(&con->arch.ivshmem);

	if (ret == IVSHMEM_MSGTYPE_STD) {
		pscom_ivshmem_recvstart(&con->arch.ivshmem, &buf, &len);
		pscom_read_done(con, buf, len);
		pscom_ivshmem_recvdone(&con->arch.ivshmem);
		return 1;
	} else if (ret == IVSHMEM_MSGTYPE_DIRECT) {
		struct iovec iov[2];
		pscom_ivshmem_recvstart_direct(&con->arch.ivshmem, iov);
		pscom_read_done(con, iov[0].iov_base, iov[0].iov_len);
		pscom_read_done(con, iov[1].iov_base, iov[1].iov_len);
		pscom_ivshmem_recvdone_direct(&con->arch.ivshmem);
		return 1;
	}

	// assert(ret == SHM_MSGTYPE_NONE || ret == SHM_MSGTYPE_DIRECT_DONE);
	return 0;
}

struct ivshmem_pending {
	struct ivshmem_pending *next;
	pscom_con_t *con;
	ivshmem_msg_t *msg;
	pscom_req_t *req;
	void *data;
};

static
void pscom_ivshmem_pending_io_conn_enq(ivshmem_conn_t *ivshmem)
{
	if (list_empty(&ivshmem_pending_io.ivshmem_conn_head)) {
		// Start polling for pending_io
		list_add_tail(&ivshmem_pending_io.poll_reader.next, &pscom.poll_reader);
	}
	list_add_tail(&ivshmem->pending_io_next_conn, &ivshmem_pending_io.ivshmem_conn_head);
}


/*
 * Enqueue a pending shared mem operation msg on connection con.
 *
 * After the io finishes call:
 *  - pscom_write_pending_done(con, req), if req != NULL
 *  - free(data), if data != NULL
 * see shm_check_pending_io().
 */

/* send iov.
   Call only if shm_cansend() == true (no check inside)!
   len must be smaller or equal SHM_BUFLEN!
*/

void pscom_ivshmem_iovsend(ivshmem_conn_t *ivshmem, struct iovec *iov, int len)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];

	/* copy to sharedmem */
	pscom_memcpy_from_iov(IVSHMEM_DATA(ivshmembuf, len), iov, len);  // def in pscom_util.h
	ivshmembuf->header.len = len;

	ivshmem_mb();

	/* Notification about the new message */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_STD;
	ivshmem->send_cur = (ivshmem->send_cur + 1) % IVSHMEM_BUFS;
}


/* send iov.
   Call only if shm_cansend() == true (no check inside)!
   iov[0].iov_len must be smaller or equal SHM_BUFLEN - sizeof(struct shm_direct_header)!
   is_psshm_ptr(iov[1].iov_base) must be true.
*/


ivshmem_msg_t *pscom_ivshmem_iovsend_direct(ivshmem_conn_t *ivshmem, struct iovec *iov)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];
	size_t len0 = iov[0].iov_len;
	char *data = IVSHMEM_DATA(ivshmembuf, len0);

	/* reference to iov[1] before header */
	struct ivshmem_direct_header *dh = (struct ivshmem_direct_header *)(data - sizeof(*dh));
	dh->base = iov[1].iov_base;
	dh->len = iov[1].iov_len;

	/* copy header to sharedmem */
	memcpy(data, iov[0].iov_base, len0);
	ivshmembuf->header.len = len0;

	ivshmem_mb();

	/* Notification about the new message */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_DIRECT;
	ivshmem->send_cur = (ivshmem->send_cur + 1) % IVSHMEM_BUFS;

	return &ivshmembuf->header;
}

static
void pscom_ivshmem_pending_io_enq(pscom_con_t *con, ivshmem_msg_t *msg, pscom_req_t *req, void *data)
{
	ivshmem_conn_t *ivshmem = &con->arch.ivshmem;
	struct ivshmem_pending *ivp = malloc(sizeof(*ivp));
	struct ivshmem_pending *old_ivp;
	ivp->next = NULL;
	ivp->con = con;
	ivp->msg = msg;
	ivp->req = req;
	ivp->data = data;

	if (!ivshmem->ivshmem_pending) {
		pscom_ivshmem_pending_io_conn_enq(ivshmem);
		ivshmem->ivshmem_pending = ivp;
	} else {
		// Append at the end
		for (old_ivp = ivshmem->ivshmem_pending; old_ivp->next; old_ivp = old_ivp->next);
		old_ivp->next = ivp;
	}
}


static
int ivshmem_cansend(ivshmem_conn_t *ivshmem)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];
	return ivshmembuf->header.msg_type == IVSHMEM_MSGTYPE_NONE;
}


static
void pscom_ivshmem_do_write(pscom_con_t *con)
{
	unsigned int len;	// Länge
	struct iovec iov[2];	// vectored I/O
	pscom_req_t *req;	// pscom request type

	req = pscom_write_get_iov(con, iov);  // pscom_io.c

	if (req && ivshmem_cansend(&con->arch.ivshmem)) {
		do_buffered_send:

			/* Buffered send : Send through the send & receive buffers. */

			len = iov[0].iov_len + iov[1].iov_len;
			len = pscom_min(len, IVSHMEM_BUFLEN);

			pscom_ivshmem_iovsend(&con->arch.ivshmem, iov, len);

			pscom_write_done(con, req, len);


}
}


/*********************************************************************/



static
void pscom_ivshmem_pending_io_conn_deq(ivshmem_conn_t *ivshmem)
{
	list_del(&ivshmem->pending_io_next_conn);
	if (list_empty(&ivshmem_pending_io.ivshmem_conn_head)) {
		// No shm_conn_t with pending io requests left. Stop polling for pending_io.
		list_del(&ivshmem_pending_io.poll_reader.next);
	}
}

static
void pscom_ivshmem_check_pending_io(ivshmem_conn_t *ivshmem)
{
	struct ivshmem_pending *ivp;
	while (((ivp = ivshmem->ivshmem_pending)) && ivp->msg->msg_type == IVSHMEM_MSGTYPE_DIRECT_DONE) {
		// finish request
		if (ivp->req) pscom_write_pending_done(ivp->con, ivp->req); // direct send done
		if (ivp->data) free(ivp->data); // indirect send done

		// Free buffer for next send
		ivp->msg->msg_type = IVSHMEM_MSGTYPE_NONE;

		// loop next sp
		ivshmem->ivshmem_pending = ivp->next;
		free(ivp);

		if (!ivshmem->ivshmem_pending) {
			// shm_conn_t is without pending io requests.
			pscom_ivshmem_pending_io_conn_deq(ivshmem);
			break;
		}
	}
}


static
int pscom_ivshmem_poll_pending_io(pscom_poll_reader_t *poll_reader)
{
	struct list_head *pos, *next;
	// For each shm_conn_t shm
	list_for_each_safe(pos, next, &ivshmem_pending_io.ivshmem_conn_head) {
		ivshmem_conn_t *ivshmem = list_entry(pos, ivshmem_conn_t, pending_io_next_conn);

		pscom_ivshmem_check_pending_io(ivshmem);
	}
	return 0;
}


void pscom_ivshmem_sock_init(pscom_sock_t *sock)
{
	ivshmem_pending_io.poll_reader.do_read = pscom_ivshmem_poll_pending_io;
	INIT_LIST_HEAD(&ivshmem_pending_io.ivshmem_conn_head);
}


static
void pscom_ivshmem_info_msg(ivshmem_conn_t *ivshmem, psivshmem_info_msg_t *msg)
{
	msg->ivshmem_buf_offset =(long) ((char*)ivshmem->local_com - (char*)ivshmem->device->ivshmem_base);
	uuid_copy(msg->uuid, *((uuid_t*)ivshmem->device->uuid));
}


static
void ivshmem_cleanup_ivshmem_conn(ivshmem_conn_t *ivshmem)
{
	int ret = -1;

	if(ivshmem->local_com){
	  ret = psivshmem_free_mem(ivshmem->device, (char*)ivshmem->local_com, sizeof(psivshmem_com_t));
	  assert(ret == 0);
	  ivshmem->local_com = NULL;
	  ivshmem->remote_com = NULL;
	  ivshmem->direct_base = NULL;
	}
}


static
void pscom_ivshmem_send(ivshmem_conn_t *ivshmem, char *buf, int len)
{
	int cur = ivshmem->send_cur;
	psivshmem_buf_t *ivshmembuf = &ivshmem->remote_com->buf[cur];  // sind header sauber aufgeteilt?????

	/* copy to sharedmem */
	memcpy(IVSHMEM_DATA(ivshmembuf, len), buf, len);
	ivshmembuf->header.len = len;

	ivshmem_mb();

	/* Notification about the new message */
	ivshmembuf->header.msg_type = IVSHMEM_MSGTYPE_STD;
	ivshmem->send_cur = (ivshmem->send_cur + 1) % IVSHMEM_BUFS;
}


static
void pscom_ivshmem_close(pscom_con_t *con)
{
	pscom_connection_t *connection = &con->pub;

	if (con->arch.ivshmem.local_com) {
		int i;
		ivshmem_conn_t *ivshmem = &con->arch.ivshmem;

		// ToDo: This must not be a blocking while loop!
		while (ivshmem->ivshmem_pending) {
			pscom_ivshmem_check_pending_io(ivshmem);
		}

		ivshmem_cleanup_ivshmem_conn(ivshmem);

		assert(list_empty(&con->poll_next_send));
		assert(list_empty(&con->poll_reader.next));

		DPRINT(1, "INFO: >>> IVSHMEM CONNECTION CLOSED! %s <<<", pscom_con_info_str(&connection->remote_con_info));
	}
}


static
void pscom_ivshmem_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_IVSHMEM;

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = pscom_ivshmem_do_read;
	con->do_write = pscom_ivshmem_do_write;
	con->close = pscom_ivshmem_close;

	con->rendezvous_size = pscom.env.rendezvous_size_ivshmem;

	pscom_con_setup_ok(con);
}


static
void ivshmem_init_ivshmem_conn(ivshmem_conn_t *ivshmem)
{
	ivshmem->local_com = NULL;
	ivshmem->remote_com = NULL;
	ivshmem->direct_base = NULL;
	ivshmem->direct_offset = 0;
}


/* pscom_ivshmem_device_handle is a static global structure that contains status intormation and memory base adresses */
static
int pscom_ivshmem_con_init(pscom_con_t *con)
{
	if(pscom_ivshmem_device_handle.status == IVSHMEM_DISABLED){
	  /* IVSHMEM_DISABLED is set if psivshmem_init_uio_device fails */
	  return -1;
	}

	con->arch.ivshmem.device = &pscom_ivshmem_device_handle;  //ToDo: just use global variable everywhere?
	return 0;
}


static
int pscom_connecting_state(pscom_con_t *con)
{
	return ((con->pub.state == PSCOM_CON_STATE_CONNECTING) || (con->pub.state == PSCOM_CON_STATE_CONNECTING_ONDEMAND));
}


static
void pscom_ivshmem_init(void)
{
	psivshmem_debug = pscom.env.debug;
	psivshmem_debug_stream = pscom_debug_stream();
	pscom_lock();
	if(pscom_ivshmem_device_handle.status != IVSHMEM_INITIALIZED){
	  /* Try to initialize the ivshmem pci device, if available
 	   * - otherwise IVSHMEM_DISABLED is set in psivshmem_init_uio_device
 	   */
	  psivshmem_init_uio_device(&pscom_ivshmem_device_handle);
	}
	pscom_unlock();
}


static
void pscom_ivshmem_destroy(void)
{
	int ret;

	ret = psivshmem_close_device(&pscom_ivshmem_device_handle);

	if(ret){
	  DPRINT(1,"ivshmem error: device was not closed sucessfully!");
	  return;
	}

	DPRINT(1,"ivshmem: plugin destroyed!");
}


#define PSCOM_INFO_IVSHMEM_MSG1 PSCOM_INFO_ARCH_STEP1
static
void pscom_ivshmem_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	precon_t *pre = con->precon;
	ivshmem_pci_dev_t * dev = con->arch.ivshmem.device;
	int diff_hosts = 0; //different hosts?
	int error = 0;
	if (dev->status!=IVSHMEM_INITIALIZED) goto error_device;
	/* handshake: */
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		/* init receive buffers */
		ivshmem_init_ivshmem_conn(&con->arch.ivshmem);
		error = pscom_ivshmem_initrecv(&con->arch.ivshmem);
		if(error) goto error_initrecv;
		psivshmem_info_msg_t msg;
		pscom_ivshmem_info_msg(&con->arch.ivshmem, &msg);
		pscom_precon_send(pre, PSCOM_INFO_IVSHMEM_MSG1, &msg, sizeof(msg));
		break;
		}
	case PSCOM_INFO_IVSHMEM_MSG1: {
		/* init send buffers */
		psivshmem_info_msg_t *msg = data;
		assert(size == sizeof(*msg));
		diff_hosts = (uuid_compare(msg->uuid, *((uuid_t*)dev->uuid)));
		if(diff_hosts){
		  /* Make sure that only the >active< site is aborting the connection
 		   * otherwise unexpected behaviour may occur.
 		   *
 		   * Special case "Passive VM is not equiped with IVShmem device"
 		   * 	-> solved by con_init
 		   *
 		   */
		  if (pscom_connecting_state(con)) goto error_diffhosts;
		  else break; // passive site does nothing and waits for ARCH_NEXT
		}
		error = pscom_ivshmem_initsend(&con->arch.ivshmem,(void*) msg->ivshmem_buf_offset);
		pscom_ivshmem_init_direct(&con->arch.ivshmem, msg->direct_offset, msg->direct_base);
		if(error) goto error_initsend;
		pscom_precon_send(pre, PSCOM_INFO_ARCH_OK, NULL, 0);
		break;
		}
	case PSCOM_INFO_ARCH_NEXT:{
		/* Cleanup ivshmem */
		ivshmem_cleanup_ivshmem_conn(&con->arch.ivshmem);
		break; /* Done (this connection attempt failed) */
		}
	case PSCOM_INFO_ARCH_OK:{
		pscom_con_guard_start(con);
		break;
		}
	case PSCOM_INFO_EOF:{
		pscom_ivshmem_init_con(con);
		break; /*Done - use this channel!*/
		}
	}

	return;

	/* Error handling */
error_device:
	DPRINT(2,"ivshmem: PCI device not available for handshake.\n");
	goto next_arch;
error_diffhosts:
	DPRINT(2,"ivshmem: handshake with %s: Differnt device uuids detected. Either executed on different hosts or wrong ivshmem device attached.\n",pscom_con_info_str(&con->pub.remote_con_info));
	goto next_arch;
error_initrecv:
error_initsend:
	DPRINT(1,"ivshmem: Unexpected error during buffer initialization!\n");
next_arch:
	ivshmem_cleanup_ivshmem_conn(&con->arch.ivshmem);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(pre);
}


pscom_plugin_t pscom_plugin = {
	.name		= "ivshmem",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_IVSHMEM,
	.priority	= PSCOM_IVSHMEM_PRIO,
	.properties     = PSCOM_PLUGIN_PROP_NOT_MIGRATABLE,
	.init		= pscom_ivshmem_init,
	.destroy	= pscom_ivshmem_destroy,
	.sock_init	= pscom_ivshmem_sock_init,
	.sock_destroy	= NULL, // ToDo ??
	.con_init	= pscom_ivshmem_con_init,
	.con_handshake  = pscom_ivshmem_handshake,
};
