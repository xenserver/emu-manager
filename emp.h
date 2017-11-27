#ifndef EMP_H
#define EMP_H

#include <stdbool.h>

/*

EMP commands take the following format:

    {"execute" : "<command>", "arguments": { "arg1" : "val1:"} }

and you should expect:

    {"return" : {} }

or

    { "error" : "descriptive error" }

-------------------------------------------------------------------------
Command           Description
----------------  -------------------------------------------------------
migrate_init      An FD is sent via the auxiliary channel, which
                  shoud be used later for migration.

migrate_live      The emulator may start migrating, while the guest
                  is still running.  This call should come after a
                  migrate_init and track_dirty command.

migrate_nonlive   The emulator should start migrating, the guest
                  should not be running.  This must come after a migrate_init.

migrate_pause     Following on from a migrate_live, the VM has been paused,
                  and no further writes to its ram may be made.

migrate_paused    After all emus have been asked to 'pause', this command
                  this command indicates, the VM is paused, and you can
                  expect no furter writes to its ram from any emu.

migrate_progress  The emulator should provide updates on
                  migration progress.
                  Arguments may include the triggers.
                  “data-sent”: <minimum sent in bytes>

migrate_abort     Due to some sort of error, migration should stop,
                  and normal operation resume - if possible.

quit              The emulator should terminate.

restore           The emulator is to restore state, created using a
                  migrate command above.  This must follow a migrate_init.

set_args          Optional command, allows emu specific arguments
                  to be sent to an emu.

track_dirty       This instructs the emulator to start dirty page tracking.
-------------------------------------------------------------------------


After an migrate_progress, repeated responses will be received as follows.
Note that the iterations field is optional.  Also not that if the bytes
"remaining" in not known (perhaps becouse you are mid iteration), '-1' can be
sent.

{
   "event" : "MIGRATION", "data":
       {
       "sent" : 500,
       "remaning" : 300
       "iteration": 3
       }
}

After migation has completed, a repsonse like below may be recived. (Note that
a result is optional)

{
   "event" : "MIGRATION", "data":
       {
       "status": "completed",
       "result": "0 0"
       }
}

*/

/*
 * This is an index into the commands array defined in emp.c. It must be kept
 * in sync.
 */
enum command_num {
    cmd_migrate_abort,
    cmd_migrate_init,
    cmd_migrate_live,
    cmd_migrate_nonlive,
    cmd_migrate_pause,
    cmd_migrate_paused,
    cmd_migrate_progress,
    cmd_quit,
    cmd_restore,
    cmd_set_args,
    cmd_track_dirty,
    cmd_number
};

struct command {
   char *name;
   bool needs_fd;
};

const struct command *command_from_num(enum command_num cmd_num);

#endif
