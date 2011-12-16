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

typedef enum {
	OBC_TRANSFER_GET,
	OBC_TRANSFER_PUT
} ObcTransferDirection;

struct obc_transfer_params {
	void *data;
	size_t size;
};

struct obc_transfer;
struct GObex;
typedef struct _GObex GObex;

typedef void (*transfer_callback_t) (struct obc_transfer *transfer,
					GError *err, void *user_data);

/* takes ownership of obc_transfer_params */
struct obc_transfer *obc_transfer_create(DBusConnection *conn,
					const char *agent,
					ObcTransferDirection dir,
					const char *filename,
					const char *name,
					const char *type,
					struct obc_transfer_params *params,
					gboolean dbus_expose,
					GError **err);

/* similar as above, but from memory. for get operations, buffer must be NULL */
struct obc_transfer *obc_transfer_create_mem(DBusConnection *conn,
					const char *agent,
					ObcTransferDirection dir,
					void *buffer, gint64 size,
					GDestroyNotify buffer_destroy_func,
					const char *name,
					const char *type,
					struct obc_transfer_params *params,
					gboolean dbus_expose,
					GError **err);

void obc_transfer_free(struct obc_transfer *transfer);

gboolean obc_transfer_set_callback(struct obc_transfer *transfer,
					transfer_callback_t func,
					void *user_data);

gboolean obc_transfer_start(struct obc_transfer *transfer,
					GObex *obex,
					GError **err);

ObcTransferDirection obc_transfer_get_dir(struct obc_transfer *transfer);
const void *obc_transfer_get_params(struct obc_transfer *transfer,
								size_t *size);
const void *obc_transfer_get_buffer(struct obc_transfer *transfer,
								size_t *size);
void obc_transfer_set_name(struct obc_transfer *transfer, const char *name);
gboolean obc_transfer_set_filename(struct obc_transfer *transfer,
					const char *filename,
					GError **err);
const char *obc_transfer_get_path(struct obc_transfer *transfer);
gint64 obc_transfer_get_size(struct obc_transfer *transfer);
gboolean obc_transfer_is_dbus_exposed(struct obc_transfer *transfer);
