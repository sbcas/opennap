#include <mysql.h>
#include "opennap.h"

extern MYSQL *Db;

void
close_db (void)
{
    mysql_close (Db);
}
