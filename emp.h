enum command_num {
    cmd_migrate_abort,
    cmd_migrate_init,
    cmd_migrate_live,
    cmd_migrate_pause,
    cmd_migrate_paused,
    cmd_migrate_progress,
    cmd_migrate_nonlive,
    cmd_restore,
    cmd_quit,
    cmd_set_args,
    cmd_number
};

struct command_names {
   char *name;
   char fd;
   enum command_num number;
};

#define EMP_COMMANDS(_cmd_name)                     \
struct command_names _cmd_name[] = {                \
    {"migrate_abort",0, cmd_migrate_abort},         \
    {"migrate_init",1, cmd_migrate_init},           \
    {"migrate_live",0, cmd_migrate_live},           \
    {"migrate_nonlive",0, cmd_migrate_nonlive},     \
    {"migrate_pause",0, cmd_migrate_pause},         \
    {"migrate_paused",0, cmd_migrate_paused},       \
    {"migrate_progress",0, cmd_migrate_progress},   \
    {"quit", 0, cmd_quit},                          \
    {"restore", 0, cmd_restore},                    \
    {"set_args", 0, cmd_set_args}                   \
}

