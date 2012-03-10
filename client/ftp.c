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
#include <string.h>

#include <gdbus.h>

#include "dbus.h"
#include "log.h"

#include "session.h"
#include "transfer.h"
#include "driver.h"
#include "ftp.h"

#define OBEX_FTP_UUID \
	"\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
#define OBEX_FTP_UUID_LEN 16

#define FTP_INTERFACE "org.openobex.FileTransfer"
#define FTP_UUID "00001106-0000-1000-8000-00805f9b34fb"
#define PCSUITE_UUID "00005005-0000-1000-8000-0002ee000001"

static DBusConnection *conn = NULL;

struct ftp_data {
	struct obc_session *session;
};

static void async_cb(struct obc_session *session, GError *err,
							gpointer user_data)
{
	DBusMessage *reply, *msg = user_data;

	if (err != NULL)
		reply = g_dbus_create_error(msg, "org.openobex.Error.Failed",
						"%s", err->message);
	else
		reply = dbus_message_new_method_return(msg);

	g_dbus_send_message(conn, reply);
	dbus_message_unref(msg);
}

static DBusMessage *change_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *folder;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &folder,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	obc_session_setpath(session, folder, async_cb, message, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static void xml_element(GMarkupParseContext *ctxt,
			const gchar *element,
			const gchar **names,
			const gchar **values,
			gpointer user_data,
			GError **gerr)
{
	DBusMessageIter dict, *iter = user_data;
	gchar *key;
	gint i;

	if (strcasecmp("folder", element) != 0 && strcasecmp("file", element) != 0)
		return;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	obex_dbus_dict_append(&dict, "Type", DBUS_TYPE_STRING, &element);

	/* FIXME: User, Group, Other permission must be reviewed */

	i = 0;
	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		key[0] = g_ascii_toupper(key[0]);
		if (g_str_equal("Size", key) == TRUE) {
			guint64 size;
			size = g_ascii_strtoll(values[i], NULL, 10);
			obex_dbus_dict_append(&dict, key, DBUS_TYPE_UINT64,
								&size);
		} else
			obex_dbus_dict_append(&dict, key, DBUS_TYPE_STRING,
								&values[i]);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static const GMarkupParser parser = {
	xml_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static void get_file_callback(struct obc_session *session,
					struct obc_transfer *transfer,
					GError *err, void *user_data)
{
	DBusMessage *msg = user_data;
	DBusMessage *reply;

	if (err)
		reply = g_dbus_create_error(msg,
					"org.openobex.Error.Failed",
					"%s", err->message);
	else
		reply = dbus_message_new_method_return(msg);

	g_dbus_send_message(conn, reply);
	dbus_message_unref(msg);
}

static void list_folder_callback(struct obc_session *session,
					struct obc_transfer *transfer,
					GError *err, void *user_data)
{
	DBusMessage *msg = user_data;
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const char *buf;

	reply = dbus_message_new_method_return(msg);

	buf = obc_transfer_get_buffer(transfer, NULL);
	if (buf[0] == '\0')
		goto done;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, buf, strlen(buf) - 1, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);

done:
	g_dbus_send_message(conn, reply);
	dbus_message_unref(msg);
}

static DBusMessage *create_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *folder;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &folder,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	obc_session_mkdir(session, folder, async_cb, message, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static DBusMessage *list_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	GError *err = NULL;

	if (!obc_session_get_mem(session, "x-obex/folder-listing",
			NULL, NULL, 0, list_folder_callback, message,
			FALSE, &err)) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static DBusMessage *get_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *target_file, *source_file;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &target_file,
				DBUS_TYPE_STRING, &source_file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (!obc_session_get_file(session, NULL, source_file,
			target_file, NULL, 0, get_file_callback, message,
			TRUE, &err)) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static DBusMessage *put_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	gchar *sourcefile, *targetfile;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &sourcefile,
					DBUS_TYPE_STRING, &targetfile,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	if (!obc_session_put_file(session, targetfile, sourcefile,
							TRUE, &err)) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	return dbus_message_new_method_return(message);
}

static DBusMessage *copy_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *filename, *destname;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &filename,
				DBUS_TYPE_STRING, &destname,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	obc_session_copy(session, filename, destname, async_cb, message, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply = g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static DBusMessage *move_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *filename, *destname;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &filename,
				DBUS_TYPE_STRING, &destname,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	obc_session_move(session, filename, destname, async_cb, message, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply = g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static DBusMessage *delete(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *file;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	obc_session_delete(session, file, async_cb, message, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply = g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	dbus_message_ref(message);

	return NULL;
}

static GDBusMethodTable ftp_methods[] = {
	{ "ChangeFolder",	"s", "",	change_folder,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "CreateFolder",	"s", "",	create_folder,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "ListFolder",		"", "aa{sv}",	list_folder,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetFile",		"ss", "",	get_file,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "PutFile",		"ss", "",	put_file,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "CopyFile",		"ss", "",	copy_file,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "MoveFile",		"ss", "",	move_file,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Delete",		"s", "",	delete,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

static void ftp_free(void *data)
{
	struct ftp_data *ftp = data;

	obc_session_unref(ftp->session);
	g_free(ftp);
}

static int ftp_probe(struct obc_session *session)
{
	struct ftp_data *ftp;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	ftp = g_try_new0(struct ftp_data, 1);
	if (!ftp)
		return -ENOMEM;

	ftp->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, FTP_INTERFACE, ftp_methods,
						NULL, NULL, ftp, ftp_free)) {
		ftp_free(ftp);
		return -ENOMEM;
	}

	return 0;
}

static void ftp_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, FTP_INTERFACE);
}

static struct obc_driver ftp = {
	.service = "FTP",
	.uuid = FTP_UUID,
	.target = OBEX_FTP_UUID,
	.target_len = OBEX_FTP_UUID_LEN,
	.probe = ftp_probe,
	.remove = ftp_remove
};

static struct obc_driver pcsuite = {
	.service = "PCSUITE",
	.uuid = PCSUITE_UUID,
	.target = OBEX_FTP_UUID,
	.target_len = OBEX_FTP_UUID_LEN,
	.probe = ftp_probe,
	.remove = ftp_remove
};

int ftp_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&ftp);
	if (err < 0)
		goto failed;

	err = obc_driver_register(&pcsuite);
	if (err < 0) {
		obc_driver_unregister(&ftp);
		goto failed;
	}

	return 0;

failed:
	dbus_connection_unref(conn);
	conn = NULL;
	return err;
}

void ftp_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&ftp);
	obc_driver_unregister(&pcsuite);
}
