/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <glib.h>
#include <gdbus.h>
#include <gobex.h>

#include "log.h"
#include "transfer.h"

#define TRANSFER_INTERFACE  "org.openobex.Transfer"
#define TRANSFER_BASEPATH   "/org/openobex"

#define DEFAULT_BUFFER_SIZE 4096

#define OBC_TRANSFER_ERROR obc_transfer_error_quark()

static guint64 counter = 0;

struct transfer_callback {
	transfer_callback_t func;
	void *data;
};

struct file_location {
	gchar *filename;		/* Local filename */
	int fd;
};

struct mem_location {
	void *buffer;			/* For Get, allocated internally */
	gint64 buffer_len;
	GDestroyNotify buffer_destroy_func;
};

struct obc_transfer {
	GObex *obex;
	ObcTransferDirection direction; /* Put or Get */
	struct file_location *file_location;
	struct mem_location *mem_location;
	struct obc_transfer_params *params;
	struct transfer_callback *callback;
	DBusConnection *conn;
	char *agent;		/* Transfer agent */
	char *path;		/* Transfer path */
	char *name;		/* Transfer object name */
	char *type;		/* Transfer object type */
	guint xfer;
	gint64 size;
	gint64 transferred;
	int err;
};

static GQuark obc_transfer_error_quark(void)
{
	return g_quark_from_static_string("obc-transfer-error-quark");
}

static void append_entry(DBusMessageIter *dict,
				const char *key, int type, void *val)
{
	DBusMessageIter entry, value;
	const char *signature;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT64:
		signature = DBUS_TYPE_UINT64_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static DBusMessage *obc_transfer_get_properties(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct obc_transfer *transfer = user_data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_entry(&dict, "Name", DBUS_TYPE_STRING, &transfer->name);
	append_entry(&dict, "Size", DBUS_TYPE_UINT64, &transfer->size);

	if (transfer->file_location != NULL)
		append_entry(&dict, "Filename", DBUS_TYPE_STRING,
					&transfer->file_location->filename);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void obc_transfer_abort(struct obc_transfer *transfer)
{
	struct transfer_callback *callback = transfer->callback;

	if (transfer->xfer > 0) {
		g_obex_cancel_transfer(transfer->xfer);
		transfer->xfer = 0;
	}

	if (transfer->obex != NULL) {
		g_obex_unref(transfer->obex);
		transfer->obex = NULL;
	}

	if (callback) {
		GError *err;

		err = g_error_new(OBC_TRANSFER_ERROR, -ECANCELED, "%s",
							strerror(ECANCELED));
		callback->func(transfer, transfer->transferred, err,
							callback->data);
		g_error_free(err);
	}
}

static DBusMessage *obc_transfer_cancel(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct obc_transfer *transfer = user_data;
	const gchar *sender;
	DBusMessage *reply;

	sender = dbus_message_get_sender(message);
	if (g_strcmp0(transfer->agent, sender) != 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	obc_transfer_abort(transfer);

	return reply;
}

static GDBusMethodTable obc_transfer_methods[] = {
	{ "GetProperties", "", "a{sv}", obc_transfer_get_properties },
	{ "Cancel", "", "", obc_transfer_cancel },
	{ }
};

static void free_file_location(struct obc_transfer *transfer)
{
	struct file_location *location = transfer->file_location;

	if (location == NULL)
		return;

	if (location->fd > 0)
		close(location->fd);

	g_free(location->filename);
	g_free(location);

	transfer->file_location = NULL;
}

static void free_mem_location(struct obc_transfer *transfer)
{
	struct mem_location *location = transfer->mem_location;

	if (location == NULL)
		return;

	transfer->mem_location = NULL;

	switch (transfer->direction) {
	case OBC_TRANSFER_GET:
		g_free(location->buffer);
		break;
	case OBC_TRANSFER_PUT:
		if (location->buffer_destroy_func != NULL)
			location->buffer_destroy_func(location->buffer);
		break;
	}

	g_free(location);
}

static void obc_transfer_free(struct obc_transfer *transfer)
{
	DBG("%p", transfer);

	if (transfer->xfer)
		g_obex_cancel_transfer(transfer->xfer);

	if (transfer->params != NULL) {
		g_free(transfer->params->data);
		g_free(transfer->params);
	}

	if (transfer->conn)
		dbus_connection_unref(transfer->conn);

	if (transfer->obex)
		g_obex_unref(transfer->obex);

	free_file_location(transfer);
	free_mem_location(transfer);

	g_free(transfer->callback);
	g_free(transfer->agent);
	g_free(transfer->name);
	g_free(transfer->type);
	g_free(transfer->path);
	g_free(transfer);
}

static struct obc_transfer *transfer_create(DBusConnection *conn,
					const char *agent,
					ObcTransferDirection dir,
					const char *name,
					const char *type,
					struct obc_transfer_params *params,
					struct file_location *file_location,
					struct mem_location *mem_location,
					GError **err)
{
	struct obc_transfer *transfer;

	assert(conn != NULL);
	assert((type != NULL) || (name != NULL));
	assert((file_location == NULL) != (mem_location == NULL));

	transfer = g_new0(struct obc_transfer, 1);
	transfer->direction = dir;
	transfer->agent = g_strdup(agent);
	transfer->file_location = file_location;
	transfer->mem_location = mem_location;
	transfer->name = g_strdup(name);
	transfer->type = g_strdup(type);
	transfer->params = params;

	/* for OBEX specific mime types we don't need to register a transfer */
	if (type != NULL &&
			(strncmp(type, "x-obex/", 7) == 0 ||
			strncmp(type, "x-bt/", 5) == 0))
		goto done;

	transfer->path = g_strdup_printf("%s/transfer%ju",
			TRANSFER_BASEPATH, counter++);

	transfer->conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (transfer->conn == NULL) {
		obc_transfer_free(transfer);
		g_set_error(err, OBC_TRANSFER_ERROR, -EIO,
						"Unable to register transfer");
		return NULL;
	}

	if (g_dbus_register_interface(transfer->conn, transfer->path,
				TRANSFER_INTERFACE,
				obc_transfer_methods, NULL, NULL,
				transfer, NULL) == FALSE) {
		obc_transfer_free(transfer);
		g_set_error(err, OBC_TRANSFER_ERROR, -EIO,
						"Unable to register transfer");
		return NULL;
	}

done:
	DBG("%p registered %s", transfer, transfer->path);

	return transfer;
}

void obc_transfer_unregister(struct obc_transfer *transfer)
{
	if (transfer->path) {
		g_dbus_unregister_interface(transfer->conn,
			transfer->path, TRANSFER_INTERFACE);
	}

	DBG("%p unregistered %s", transfer, transfer->path);

	obc_transfer_free(transfer);
}

static gboolean transfer_open_file(struct obc_transfer *transfer, GError **err)
{
	struct file_location *location = transfer->file_location;
	int fd;
	struct stat st;

	if (transfer->direction == OBC_TRANSFER_PUT) {
		DBG("opening file: %s", location->filename);
		fd = open(location->filename, O_RDONLY);
	} else {
		fd = open(location->filename ? : transfer->name,
					O_WRONLY | O_CREAT | O_TRUNC, 0600);
		DBG("creating file: %s", location->filename);
	}

	if (fd < 0) {
		error("open(): %s (%d)", strerror(errno), errno);
		g_set_error(err, OBC_TRANSFER_ERROR, -EIO,
						"Cannot open file");
		return FALSE;
	}

	if (transfer->direction == OBC_TRANSFER_PUT) {
		if (fstat(fd, &st) < 0) {
			error("fstat(): %s (%d)", strerror(errno), errno);
			g_set_error(err, OBC_TRANSFER_ERROR, -EIO,
						"Cannot get file size");
			return FALSE;
		}

		transfer->size = st.st_size;
	}

	location->fd = fd;
	return TRUE;
}

struct obc_transfer *obc_transfer_create(DBusConnection *conn,
					const char *agent,
					ObcTransferDirection dir,
					const char *filename,
					const char *name,
					const char *type,
					struct obc_transfer_params *params,
					GError **err)
{
	struct file_location *file_location;
	struct obc_transfer *transfer;

	assert(filename != NULL);

	file_location = g_malloc0(sizeof(*file_location));
	file_location->filename = g_strdup(filename);

	transfer = transfer_create(conn, agent, dir, name, type, params,
					file_location, NULL, err);
	if (transfer == NULL)
		return NULL;

	if (!transfer_open_file(transfer, err)) {
		obc_transfer_free(transfer);
		return NULL;
	}

	return transfer;
}

struct obc_transfer *obc_transfer_create_mem(DBusConnection *conn,
					const char *agent,
					ObcTransferDirection dir,
					void *buffer, gint64 size,
					GDestroyNotify buffer_destroy_func,
					const char *name,
					const char *type,
					struct obc_transfer_params *params,
					GError **err)
{
	struct mem_location *mem_location;
	struct obc_transfer *transfer;

	assert((dir == OBC_TRANSFER_PUT) || (buffer == NULL));

	mem_location = g_malloc0(sizeof(*mem_location));

	switch (dir) {
	case OBC_TRANSFER_GET:
		assert(buffer == NULL);
		mem_location->buffer_len = 1024;
		mem_location->buffer = g_malloc0(mem_location->buffer_len);
		break;
	case OBC_TRANSFER_PUT:
		assert(buffer != NULL);
		mem_location->buffer = buffer;
		mem_location->buffer_len = size;
		mem_location->buffer_destroy_func = buffer_destroy_func;
		break;
	}

	transfer = transfer_create(conn, agent, dir, name, type, params,
					NULL, mem_location, err);
	if (transfer == NULL)
		return NULL;

	if (dir == OBC_TRANSFER_PUT)
		transfer->size = size;

	return transfer;
}

static void obc_transfer_read(struct obc_transfer *transfer,
						const void *buf, gsize len)
{
	struct mem_location *location = transfer->mem_location;
	gsize bsize;

	assert(location != NULL);

	/* copy all buffered data */
	bsize = location->buffer_len - transfer->transferred;

	if (bsize < len) {
		location->buffer_len += len - bsize;
		location->buffer = g_realloc(location->buffer,
							location->buffer_len);
	}

	memcpy(location->buffer + transfer->transferred, buf, len);

	transfer->transferred += len;
}

static void get_buf_xfer_complete(GObex *obex, GError *err, gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	struct mem_location *location = transfer->mem_location;
	gsize bsize;

	assert(location != NULL);

	transfer->xfer = 0;

	if (err) {
		transfer->err = err->code;
		goto done;
	}

	if (transfer->transferred > 0 &&
		((char *) location->buffer)[transfer->transferred - 1] == '\0')
		goto done;

	bsize = location->buffer_len - transfer->transferred;
	if (bsize < 1) {
		location->buffer_len += 1;
		location->buffer = g_realloc(location->buffer,
						location->buffer_len);
	}

	((char *) location->buffer)[transfer->transferred] = '\0';
	transfer->size = strlen(location->buffer);

done:
	if (callback)
		callback->func(transfer, transfer->size, err, callback->data);
}

static void get_buf_xfer_progress(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	GObexPacket *req;
	GObexHeader *hdr;
	const guint8 *buf;
	gsize len;
	guint8 rspcode;
	gboolean final;

	if (err != NULL) {
		get_buf_xfer_complete(obex, err, transfer);
		return;
	}

	rspcode = g_obex_packet_get_operation(rsp, &final);
	if (rspcode != G_OBEX_RSP_SUCCESS && rspcode != G_OBEX_RSP_CONTINUE) {
		err = g_error_new(OBC_TRANSFER_ERROR, rspcode,
					"Transfer failed (0x%02x)", rspcode);
		get_buf_xfer_complete(obex, err, transfer);
		g_error_free(err);
		return;
	}

	hdr = g_obex_packet_get_header(rsp, G_OBEX_HDR_APPARAM);
	if (hdr) {
		g_obex_header_get_bytes(hdr, &buf, &len);
		if (len != 0) {
			if (transfer->params == NULL)
				transfer->params =
					g_new0(struct obc_transfer_params, 1);
			else
				g_free(transfer->params->data);

			transfer->params->data = g_memdup(buf, len);
			transfer->params->size = len;
		}
	}

	hdr = g_obex_packet_get_body(rsp);
	if (hdr) {
		g_obex_header_get_bytes(hdr, &buf, &len);
		if (len != 0)
			obc_transfer_read(transfer, buf, len);
	}

	if (rspcode == G_OBEX_RSP_SUCCESS) {
		get_buf_xfer_complete(obex, err, transfer);
		return;
	}

	if (!g_obex_srm_active(obex)) {
		req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);

		transfer->xfer = g_obex_send_req(obex, req, -1,
							get_buf_xfer_progress,
							transfer, &err);
	}

	if (callback && transfer->transferred != transfer->size)
		callback->func(transfer, transfer->transferred, err,
							callback->data);
}

static void xfer_complete(GObex *obex, GError *err, gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;

	transfer->xfer = 0;

	if (err) {
		transfer->err = err->code;
		goto done;
	}

	transfer->size = transfer->transferred;

done:
	if (callback)
		callback->func(transfer, transfer->size, err, callback->data);
}

static gboolean get_xfer_progress(const void *buf, gsize len,
							gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	struct file_location *location = transfer->file_location;

	assert(location != NULL);
	assert(location->fd > 0);

	if (write(location->fd, buf, len) < (ssize_t) len) {
		transfer->err = -errno;
		return FALSE;
	}

	if (callback && transfer->transferred != transfer->size)
		callback->func(transfer, transfer->transferred, NULL,
							callback->data);

	return TRUE;
}

static gssize put_buf_xfer_progress(void *buf, gsize len, gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	struct mem_location *location = transfer->mem_location;
	gsize size;

	assert(location != NULL);

	if (transfer->transferred == transfer->size)
		return 0;

	size = transfer->size - transfer->transferred;
	size = len > size ? len : size;
	if (size == 0)
		return 0;

	memcpy(buf, location->buffer + transfer->transferred, size);

	transfer->transferred += size;

	if (callback)
		callback->func(transfer, transfer->transferred, NULL,
							callback->data);

	return size;
}

static gssize put_xfer_progress(void *buf, gsize len, gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	struct file_location *location = transfer->file_location;
	gssize size;

	size = read(location->fd, buf, len);
	if (size <= 0) {
		transfer->err = -errno;
		return size;
	}

	if (callback)
		callback->func(transfer, transfer->transferred, NULL,
							callback->data);

	transfer->transferred += size;

	return size;
}

gboolean obc_transfer_set_callback(struct obc_transfer *transfer,
					transfer_callback_t func,
					void *user_data)
{
	struct transfer_callback *callback;

	if (transfer->callback != NULL)
		return FALSE;

	callback = g_new0(struct transfer_callback, 1);
	callback->func = func;
	callback->data = user_data;

	transfer->callback = callback;

	return TRUE;
}

static gboolean transfer_start_get(struct obc_transfer *transfer, GError **err)
{
	GObexPacket *req;
	GObexDataConsumer data_cb;
	GObexFunc complete_cb;
	GObexResponseFunc rsp_cb = NULL;

	if (transfer->xfer > 0) {
		g_set_error(err, OBC_TRANSFER_ERROR, -EALREADY,
						"Transfer already started");
		return FALSE;
	}

	if (transfer->mem_location != NULL)
		rsp_cb = get_buf_xfer_progress;
	else {
		data_cb = get_xfer_progress;
		complete_cb = xfer_complete;
	}

	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);

	if (transfer->name != NULL)
		g_obex_packet_add_unicode(req, G_OBEX_HDR_NAME,
							transfer->name);

	if (transfer->type != NULL)
		g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, transfer->type,
						strlen(transfer->type) + 1);

	if (transfer->params != NULL)
		g_obex_packet_add_bytes(req, G_OBEX_HDR_APPARAM,
						transfer->params->data,
						transfer->params->size);

	if (rsp_cb)
		transfer->xfer = g_obex_send_req(transfer->obex, req, -1,
						rsp_cb, transfer, err);
	else
		transfer->xfer = g_obex_get_req_pkt(transfer->obex, req,
						data_cb, complete_cb, transfer,
						err);

	if (transfer->xfer == 0)
		return FALSE;

	return TRUE;
}

static gboolean transfer_start_put(struct obc_transfer *transfer, GError **err)
{
	GObexPacket *req;
	GObexDataProducer data_cb;

	if (transfer->xfer > 0) {
		g_set_error(err, OBC_TRANSFER_ERROR, -EALREADY,
						"Transfer already started");
		return FALSE;
	}

	if (transfer->mem_location != NULL)
		data_cb = put_buf_xfer_progress;
	else
		data_cb = put_xfer_progress;

	req = g_obex_packet_new(G_OBEX_OP_PUT, FALSE, G_OBEX_HDR_INVALID);

	if (transfer->name != NULL)
		g_obex_packet_add_unicode(req, G_OBEX_HDR_NAME,
							transfer->name);

	if (transfer->type != NULL)
		g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, transfer->type,
						strlen(transfer->type) + 1);

	if (transfer->size < UINT32_MAX)
		g_obex_packet_add_uint32(req, G_OBEX_HDR_LENGTH, transfer->size);

	if (transfer->params != NULL)
		g_obex_packet_add_bytes(req, G_OBEX_HDR_APPARAM,
						transfer->params->data,
						transfer->params->size);

	transfer->xfer = g_obex_put_req_pkt(transfer->obex, req, data_cb,
						xfer_complete, transfer,
						err);
	if (transfer->xfer == 0)
		return FALSE;

	return TRUE;
}

gboolean obc_transfer_start(struct obc_transfer *transfer, GObex *obex,
								GError **err)
{
	transfer->obex = g_obex_ref(obex);

	switch (transfer->direction) {
	case OBC_TRANSFER_GET:
		return transfer_start_get(transfer, err);
	case OBC_TRANSFER_PUT:
		return transfer_start_put(transfer, err);
	}

	g_set_error(err, OBC_TRANSFER_ERROR, -ENOTSUP, "Not supported");
	return FALSE;
}

ObcTransferDirection obc_transfer_get_dir(struct obc_transfer *transfer)
{
	return transfer->direction;
}

const void *obc_transfer_get_params(struct obc_transfer *transfer, size_t *size)
{
	if (transfer->params == NULL)
		return NULL;

	if (size != NULL)
		*size = transfer->params->size;

	return transfer->params->data;
}

const void *obc_transfer_get_buffer(struct obc_transfer *transfer, size_t *size)
{
	if (transfer->mem_location == NULL)
		return NULL;

	if (size != NULL)
		*size = transfer->size;

	return transfer->mem_location->buffer;
}

void obc_transfer_set_name(struct obc_transfer *transfer, const char *name)
{
	g_free(transfer->name);
	transfer->name = g_strdup(name);
}

gboolean obc_transfer_set_filename(struct obc_transfer *transfer,
					const char *filename,
					GError **err)
{
	struct file_location *location = transfer->file_location;
	char *old = location->filename;

	location->filename = g_strdup(filename);

	if ((old == NULL) || (filename == NULL) || !g_strcmp0(old, filename))
		goto done;

	if (location->fd > 0) {
		close(location->fd);
		location->fd = 0;
	}

	if (!transfer_open_file(transfer, err)) {
		g_free(old);
		return FALSE;
	}

done:
	g_free(old);
	return TRUE;
}

const char *obc_transfer_get_path(struct obc_transfer *transfer)
{
	return transfer->path;
}

gint64 obc_transfer_get_size(struct obc_transfer *transfer)
{
	return transfer->size;
}
