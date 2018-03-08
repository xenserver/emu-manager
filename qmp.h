#ifndef QMP_H
#define QMP_H

enum qmp_command_num {
    cmd_qmp_capabilities,
    cmd_xen_set_global_dirty_log,
    qmp_cmd_number
};

const struct command *qmp_command_from_num(enum qmp_command_num cmd_num);

#endif

