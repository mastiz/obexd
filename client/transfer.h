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

struct obc_transfer_params {
	void *data;
	size_t size;
};

struct obc_transfer;

typedef void (*transfer_callback_t) (struct obc_transfer *transfer,
					gint64 transferred, GError *err,
					void *user_data);

struct obc_transfer *obc_transfer_register(DBusConnection *conn,
					GObex *obex,
					const char *agent,
					const char *filename,
					const char *name,
					const char *type,
					struct obc_transfer_params *params);

void obc_transfer_unregister(struct obc_transfer *transfer);

gboolean obc_transfer_set_callback(struct obc_transfer *transfer,
					transfer_callback_t func,
					void *user_data);

int obc_transfer_get(struct obc_transfer *transfer);
int obc_transfer_put(struct obc_transfer *transfer);

const void *obc_transfer_get_params(struct obc_transfer *transfer,
								size_t *size);
const void *obc_transfer_get_buffer(struct obc_transfer *transfer,
								size_t *size);
void obc_transfer_set_buffer(struct obc_transfer *transfer, char *buffer);

void obc_transfer_set_name(struct obc_transfer *transfer, const char *name);
void obc_transfer_set_filename(struct obc_transfer *transfer,
					const char *filename);
const char *obc_transfer_get_path(struct obc_transfer *transfer);
gint64 obc_transfer_get_size(struct obc_transfer *transfer);
int obc_transfer_set_file(struct obc_transfer *transfer);
