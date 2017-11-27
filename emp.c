#include "emp.h"
#include <assert.h>

static struct command commands[] = {
    {"migrate_abort", false},
    {"migrate_init", true},
    {"migrate_live", false},
    {"migrate_nonlive", false},
    {"migrate_pause", false},
    {"migrate_paused", false},
    {"migrate_progress", false},
    {"quit", false},
    {"restore", false},
    {"set_args", false},
    {"track_dirty", false}
};

const struct command *command_from_num(enum command_num cmd_num)
{
    assert(cmd_num < cmd_number);
    return &commands[cmd_num];
}
