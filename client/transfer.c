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

#include "dbus.h"
#include "log.h"
#include "transfer.h"

#define TRANSFER_INTERFACE  "org.openobex.Transfer"
#define TRANSFER_BASEPATH   "/org/openobex"
#define TRANSFER_TMP_TEMPLATE  "/tmp/obex-client-get-XXXXXX"

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

struct dbus_data {
	DBusConnection *conn;
	char *agent;
	char *path;			/* Transfer path */
};

struct obc_transfer {
	GObex *obex;
	ObcTransferDirection direction; /* Put or Get */
	struct file_location *file_location;
	struct mem_location *mem_location;
	struct obc_transfer_params *params;
	struct transfer_callback *callback;
	struct dbus_data *dbus_data;
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

static void __obc_transfer_append_properties(struct obc_transfer *transfer,
						DBusMessageIter *dict)
{
	obex_dbus_dict_append(dict, "Name", DBUS_TYPE_STRING, &transfer->name);

	if (transfer->file_location != NULL)
		obex_dbus_dict_append(dict, "Filename", DBUS_TYPE_STRING,
					&transfer->file_location->filename);

	obex_dbus_dict_append(dict, "Size", DBUS_TYPE_UINT64, &transfer->size);
}

static DBusMessage *obc_transfer_get_properties(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct obc_transfer *transfer = user_data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;

	assert(transfer->dbus_data != NULL);

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	__obc_transfer_append_properties(transfer, &dict);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void transfer_notify_progress(struct obc_transfer *transfer)
{
	struct transfer_callback *callback = transfer->callback;

	DBG("%p", transfer);

	if ((callback != NULL) && (transfer->transferred < transfer->size)) {
		transfer->callback = NULL;
		callback->func(transfer, transfer->transferred, NULL,
								callback->data);
		g_free(callback);
	}
}

static void transfer_notify_complete(struct obc_transfer *transfer)
{
	struct transfer_callback *callback = transfer->callback;

	DBG("%p", transfer);

	if (callback != NULL) {
		transfer->callback = NULL;
		callback->func(transfer, transfer->transferred, NULL,
								callback->data);
		g_free(callback);
	}
}

static void transfer_notify_error(struct obc_transfer *transfer, GError *err)
{
	struct transfer_callback *callback = transfer->callback;

	if ((transfer->direction == OBC_TRANSFER_GET) &&
					(transfer->file_location != NULL))
		unlink(transfer->file_location->filename);

	if (callback != NULL) {
		transfer->callback = NULL;
		callback->func(transfer, transfer->transferred, err,
								callback->data);
		g_free(callback);
	}
}

static void obc_transfer_abort(struct obc_transfer *transfer)
{
	GError *err;

	if (transfer->xfer > 0) {
		g_obex_cancel_transfer(transfer->xfer);
		transfer->xfer = 0;
	}

	if (transfer->obex != NULL) {
		g_obex_unref(transfer->obex);
		transfer->obex = NULL;
	}

	err = g_error_new(OBC_TRANSFER_ERROR, -ECANCELED, "%s",
							strerror(ECANCELED));
	transfer_notify_error(transfer, err);
	g_error_free(err);
}

static DBusMessage *obc_transfer_cancel(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct obc_transfer *transfer = user_data;
	const gchar *sender;
	DBusMessage *reply;

	assert(transfer->dbus_data != NULL);

	sender = dbus_message_get_sender(message);
	if (g_strcmp0(transfer->dbus_data->agent, sender) != 0)
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

static void dbus_data_free(struct dbus_data *data)
{
	if (data == NULL)
		return;

	if (data->path != NULL) {
		g_dbus_unregister_interface(data->conn,
					    data->path, TRANSFER_INTERFACE);

		DBG("unregistered %s", data->path);
	}

	dbus_connection_unref(data->conn);
	g_free(data->path);
	g_free(data->agent);
	g_free(data);
}

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

void obc_transfer_free(struct obc_transfer *transfer)
{
	DBG("%p", transfer);

	if (transfer->xfer)
		g_obex_cancel_transfer(transfer->xfer);

	if (transfer->params != NULL) {
		g_free(transfer->params->data);
		g_free(transfer->params);
	}

	if (transfer->obex)
		g_obex_unref(transfer->obex);

	dbus_data_free(transfer->dbus_data);
	free_file_location(transfer);
	free_mem_location(transfer);

	g_free(transfer->callback);
	g_free(transfer->name);
	g_free(transfer->type);
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
					gboolean dbus_expose,
					GError **err)
{
	struct obc_transfer *transfer;

	assert(conn != NULL);
	assert((type != NULL) || (name != NULL));
	assert((file_location == NULL) != (mem_location == NULL));

	transfer = g_new0(struct obc_transfer, 1);
	transfer->direction = dir;
	transfer->file_location = file_location;
	transfer->mem_location = mem_location;
	transfer->name = g_strdup(name);
	transfer->type = g_strdup(type);
	transfer->params = params;

	if (!dbus_expose) {
		DBG("%p created but not registered", transfer);
		goto done;
	}

	transfer->dbus_data = g_malloc0(sizeof(struct dbus_data));
	transfer->dbus_data->conn = dbus_connection_ref(conn);
	transfer->dbus_data->agent = g_strdup(agent);
	transfer->dbus_data->path = g_strdup_printf("%s/transfer%ju",
						TRANSFER_BASEPATH, counter++);

	if (g_dbus_register_interface(transfer->dbus_data->conn,
				transfer->dbus_data->path, TRANSFER_INTERFACE,
				obc_transfer_methods, NULL,
				NULL, transfer, NULL) == FALSE) {
		g_free(transfer->dbus_data->path);
		transfer->dbus_data->path = NULL;
		obc_transfer_free(transfer);
		g_set_error(err, OBC_TRANSFER_ERROR, -EIO,
						"Unable to register transfer");
		return NULL;
	}

	DBG("%p registered %s", transfer, transfer->dbus_data->path);

done:
	return transfer;
}

static gboolean transfer_open_file(struct obc_transfer *transfer, GError **err)
{
	struct file_location *location = transfer->file_location;
	int fd;
	struct stat st;

	if (transfer->direction == OBC_TRANSFER_PUT) {
		DBG("opening file: %s", location->filename);
		fd = open(location->filename, O_RDONLY);
	} else if ((location->filename != NULL) && location->filename[0]) {
		fd = open(location->filename, O_WRONLY | O_CREAT | O_TRUNC,
									0600);
		DBG("creating file: %s", location->filename);
	} else {
		mode_t old_mask = umask(033);

		g_free(location->filename);
		location->filename = g_strdup(TRANSFER_TMP_TEMPLATE);
		fd = mkstemp(location->filename);
		umask(old_mask);

		DBG("creating temporary file: %s", location->filename);
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
					gboolean dbus_expose,
					GError **err)
{
	struct file_location *file_location;
	struct obc_transfer *transfer;

	assert(filename != NULL);

	file_location = g_malloc0(sizeof(*file_location));
	file_location->filename = g_strdup(filename);

	transfer = transfer_create(conn, agent, dir, name, type, params,
					file_location, NULL, dbus_expose, err);
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
					gboolean dbus_expose,
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
					NULL, mem_location, dbus_expose, err);
	if (transfer == NULL)
		return NULL;

	if (dir == OBC_TRANSFER_PUT)
		transfer->size = size;

	return transfer;
}

static void handle_get_apparams(struct obc_transfer *transfer, GObexPacket *rsp)
{
	GObexHeader *hdr;
	const guint8 *buf;
	gsize len;

	hdr = g_obex_packet_get_header(rsp, G_OBEX_HDR_APPARAM);
	if (hdr != NULL) {
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
}

static gboolean handle_get_body(struct obc_transfer *transfer, GObexPacket *rsp)
{
	GObexHeader *body = g_obex_packet_get_body(rsp);
	GError *err;
	const guint8 *buf;
	gsize len;

	if (body == NULL)
		return TRUE;

	g_obex_header_get_bytes(body, &buf, &len);
	if (len == 0)
		return TRUE;

	if (transfer->file_location != NULL) {
		struct file_location *location = transfer->file_location;

		if (write(location->fd, buf, len) < (ssize_t) len) {
			err = g_error_new(OBC_TRANSFER_ERROR, -EIO,
								"Write failed");
			goto failed;
		}
	} else {
		struct mem_location *location = transfer->mem_location;
		gint64 req_size;

		assert(location != NULL);

		/* for convenience, leave space for final null character */
		req_size = transfer->transferred + len + 1;

		if (location->buffer_len < req_size) {
			while (location->buffer_len < req_size)
				location->buffer_len *= 2;

			location->buffer = g_realloc(location->buffer,
							location->buffer_len);
		}

		memcpy(location->buffer + transfer->transferred, buf, len);
	}

	transfer->transferred += len;

	return TRUE;

failed:
	error("%s", err->message);
	transfer_notify_error(transfer, err);
	g_clear_error(&err);
	return FALSE;
}

static gssize put_get_data(void *buf, gsize len, gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	GObexPacket *req;
	GError *err = NULL;
	gssize size;

	if (transfer->file_location != NULL) {
		size = read(transfer->file_location->fd, buf, len);
		if (size < 0)
			goto failed;
	} else {
		struct mem_location *location = transfer->mem_location;

		assert(location != NULL);

		if (transfer->transferred == transfer->size)
			return 0;

		size = transfer->size - transfer->transferred;
		size = (gssize) len > size ? (gssize) len : size;

		if (size > 0)
			memcpy(buf, location->buffer + transfer->transferred,
									size);
	}

	transfer->transferred += size;

	transfer_notify_progress(transfer);

	return size;

failed:
	err = g_error_new(OBC_TRANSFER_ERROR, -EIO, "Read failed");
	transfer_notify_error(transfer, err);
	g_clear_error(&err);

	req = g_obex_packet_new(G_OBEX_OP_ABORT, TRUE, G_OBEX_HDR_INVALID);
	g_obex_send_req(transfer->obex, req, -1, NULL, NULL, NULL);

	return -1;
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

static void xfer_response(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct obc_transfer *transfer = user_data;
	GObexPacket *req;
	gboolean rspcode, final;

	transfer->xfer = 0;

	if (err != NULL) {
		transfer_notify_error(transfer, err);
		return;
	}

	rspcode = g_obex_packet_get_operation(rsp, &final);
	if (rspcode != G_OBEX_RSP_SUCCESS && rspcode != G_OBEX_RSP_CONTINUE) {
		err = g_error_new(OBC_TRANSFER_ERROR, rspcode,
					"Transfer failed (0x%02x)", rspcode);
		transfer_notify_error(transfer, err);
		g_error_free(err);
		return;
	}

	if (transfer->direction == OBC_TRANSFER_GET) {
		handle_get_apparams(transfer, rsp);

		if (handle_get_body(transfer, rsp) == FALSE)
			return;
	}

	if (rspcode == G_OBEX_RSP_SUCCESS) {
		if (transfer->mem_location != NULL) {
			char *buf = transfer->mem_location->buffer;

			buf[transfer->transferred] = '\0';
		}

		transfer->size = transfer->transferred;

		transfer_notify_complete(transfer);
		return;
	}

	if (transfer->direction == OBC_TRANSFER_PUT) {
		req = g_obex_packet_new(G_OBEX_OP_PUT, FALSE,
							G_OBEX_HDR_INVALID);
		g_obex_packet_add_body(req, put_get_data, transfer);
	} else if (!g_obex_srm_active(transfer->obex)) {
		req = g_obex_packet_new(G_OBEX_OP_GET, TRUE,
							G_OBEX_HDR_INVALID);
	} else
		return;

	transfer->xfer = g_obex_send_req(obex, req, -1, xfer_response,
							transfer, &err);
}

static gboolean transfer_start_obex(struct obc_transfer *transfer, GError **err)
{
	GObexPacket *req;
	guint8 opcode;

	if (transfer->xfer > 0) {
		g_set_error(err, OBC_TRANSFER_ERROR, -EALREADY,
						"Transfer already started");
		return FALSE;
	}

	if (transfer->direction == OBC_TRANSFER_PUT)
		opcode = G_OBEX_OP_PUT;
	else
		opcode = G_OBEX_OP_GET;

	req = g_obex_packet_new(opcode, FALSE, G_OBEX_HDR_INVALID);

	if (transfer->name != NULL)
		g_obex_packet_add_unicode(req, G_OBEX_HDR_NAME,
							transfer->name);

	if (transfer->type != NULL)
		g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, transfer->type,
						strlen(transfer->type) + 1);

	if (transfer->direction == OBC_TRANSFER_PUT) {
		if (transfer->size < UINT32_MAX)
			g_obex_packet_add_uint32(req, G_OBEX_HDR_LENGTH,
								transfer->size);
	}

	if (transfer->params != NULL)
		g_obex_packet_add_bytes(req, G_OBEX_HDR_APPARAM,
						transfer->params->data,
						transfer->params->size);

	transfer->xfer = g_obex_send_req(transfer->obex, req, -1, xfer_response,
							transfer, err);
	if (transfer->xfer > 0)
		return TRUE;

	return FALSE;
}

gboolean obc_transfer_start(struct obc_transfer *transfer, GObex *obex,
								GError **err)
{
	if (transfer->xfer > 0) {
		g_set_error(err, OBC_TRANSFER_ERROR, -EALREADY,
						"Transfer already started");
		return FALSE;
	}

	transfer->obex = g_obex_ref(obex);

	return transfer_start_obex(transfer, err);
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
	if (transfer->dbus_data == NULL)
		return NULL;

	return transfer->dbus_data->path;
}

gint64 obc_transfer_get_size(struct obc_transfer *transfer)
{
	return transfer->size;
}

gboolean obc_transfer_is_dbus_exposed(struct obc_transfer *transfer)
{
	return (transfer->dbus_data != NULL);
}
