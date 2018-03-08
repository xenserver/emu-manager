#include "qmp.h"
#include <emp.h>

#include <assert.h>


static struct command qmp_commands[] = {
    { "qmp_capabilities", false },
    { "xen-set-global-dirty-log", false }
};

const struct command *qmp_command_from_num(enum qmp_command_num cmd_num)
{
    assert(cmd_num < qmp_cmd_number);
    return &qmp_commands[cmd_num];
}

