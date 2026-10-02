#include <sqlite3.h>

/* sqlite3_db_config is variadic and so is not imported into Swift. Wrap the one option we need.
   SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE disables the implicit WAL checkpoint SQLite runs when the LAST
   connection to a WAL database closes. We set it on read connections so opening a database merely to
   scan it can never rewrite the user's file (a checkpoint moves -wal frames into the main file and
   bumps its mtime). The numeric fallback keeps this compiling against older SQLite headers. */
#ifndef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
#define SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE 1013
#endif

static inline int hg_sqlite_disable_checkpoint_on_close(sqlite3 *db) {
    return sqlite3_db_config(db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, (int *)0);
}
