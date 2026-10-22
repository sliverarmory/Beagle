//! Register the statically linked GraphQLite engine on a bundled SQLite connection.

use anyhow::{Context, Result};
use rusqlite::{Connection, ffi};
use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn sqlite3_graphqlite_init(
        db: *mut ffi::sqlite3,
        error: *mut *mut c_char,
        api: *const ffi::sqlite3_api_routines,
    ) -> c_int;
}

pub(crate) fn initialize(connection: &Connection) -> Result<()> {
    let mut error = std::ptr::null_mut();
    // SAFETY: GraphQLite is compiled with SQLITE_CORE against the same SQLite
    // headers and implementation as rusqlite. Its API-table argument is unused
    // in this mode. The connection is live and exclusively owned during setup;
    // GraphQLite registers per-connection state that SQLite frees on close.
    let code =
        unsafe { sqlite3_graphqlite_init(connection.handle(), &mut error, std::ptr::null()) };
    let message = if error.is_null() {
        None
    } else {
        // SQLite extension initialization errors use SQLite's allocator.
        let message = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        unsafe { ffi::sqlite3_free(error.cast()) };
        Some(message)
    };
    if code != ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(
            ffi::Error::new(code),
            message,
        ))
        .context("initialize built-in GraphQLite");
    }
    Ok(())
}
