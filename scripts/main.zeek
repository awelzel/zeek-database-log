module Database;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	const MySQL = "mysql";
	const PostgreSQL = "postgresql";

	type Info: record {
		## Timestamp for when the first event for this entry happened.
		ts: time    &log;
		## Unique ID for the connection.
		uid: string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## What kind of database this is.
		db: string &log;
		## The server version announced in the initial handshake packet.
		server_version: string &log &optional;
		## The username in the client's handshake packet.
		username: string &log &optional;
		## The auth plugin in the server's initial handshake packet (MySQL)
		server_auth_plugin: string &log &optional;
		## The auth plugin in the client's handshake packet (MySQL)
		client_auth_plugin: string &log &optional;
		## The plugin requested by the server in an mysql_auth_switch_request (MySQL)
		server_auth_switch_plugin: string &log &optional;

		## Error code as string (in case other databases use E123 style codes).
		last_error_code: string &log &optional;

		## Last observed error message.
		last_error_msg: string &log &optional;

		## Whether we identified the connection switching to SSL.
		ssl: bool &log &optional;

		## Whether the login was successful.
		success: bool &log &optional;

		## Has this entry been logged?
		logged: bool &default=F;
	};

	global log_database: event(rec: Info);

	global finalize_database: Conn::RemovalHook;

}

redef record connection += {
	database_info: Info &optional;
};

function set_session(c: connection, db: string): Info {
	if ( ! c?$database_info ) {
		c$database_info = [
			$ts=network_time(),
			$uid=c$uid,
			$id=c$id,
			$db=db,
		];
		Conn::register_removal_hook(c, finalize_database);
	}

	return c$database_info;
}

event mysql_server_version(c: connection, ver: string) {
	local info = set_session(c, MySQL);
	info$server_version = ver;
	info$ssl = F;
}

event mysql_handshake(c: connection, username: string) {
	local info = set_session(c, MySQL);
	info$username = username;
}

event mysql_auth_plugin(c: connection, is_orig: bool, name: string, data: string) {
	local info = set_session(c, MySQL);
	if ( is_orig )
		info$client_auth_plugin = name;
	else
		info$server_auth_plugin = name;
}

event mysql_auth_switch_request(c: connection, name: string, data: string) {
	local info = set_session(c, MySQL);
	info$server_auth_switch_plugin = name;
}

event mysql_ok(c: connection, affected_rows: count) {
	local info = set_session(c, MySQL);
	if ( info$logged )
		return;

	info$success = T;

	hook finalize_database(c);
}

event mysql_error(c: connection, code: count, msg: string) {
	local info = set_session(c, MySQL);
	if ( info$logged )
		return;

	local inital_error = ! c?$database_info;
	info$last_error_code = cat(code);
	info$last_error_msg = msg;
	info$success = F;

	# If the first thing we see is a mysql_error(), just write it out immediately.
	if ( inital_error ) {
		Log::write(LOG, c$database_info);
		delete c$database_info;
	}
}

event mysql_ssl_request(c: connection) {
	local info = set_session(c, MySQL);
	info$ssl = T;

	# Don't expect anything afterwards.
	Log::write(LOG, c$database_info);
	delete c$database_info;
}

hook finalize_database(c: connection) {
	if ( c?$database_info && ! c$database_info$logged ) {
		Log::write(LOG, c$database_info);
		c$database_info$logged = T;
	}
}

event zeek_init() {
	Log::create_stream(LOG, [$columns=Info, $ev=log_database, $path="database", $policy=log_policy]);
}
