#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

#include "lib.h"
#include "em-client.h"

enum operation_mode {
    op_save,
    op_pvsave,
    op_restore,
    op_pvrestore,
    op_end,
    op_invalid,
};

enum protocol {
    emp,
    qmp,
};

enum state {
    not_done,
    started,
    live_done,
    all_done,
    result_sent
};

enum stages {
    stage_enabled,
    stage_start,
    stage_init,
    stage_live,
    stage_pause,
    stage_paused,
    stage_stopcopy
};

#define STAGE_ENABLED  (1 << stage_enabled)
#define STAGE_START    (1 << stage_start)
#define STAGE_INIT     (1 << stage_init)
#define STAGE_LIVE     (1 << stage_live)
#define STAGE_PAUSE    (1 << stage_pause)
#define STAGE_PAUSED   (1 << stage_paused)
#define STAGE_STOPCOPY (1 << stage_stopcopy)

#define FULL_LIVE    STAGE_START | STAGE_INIT | STAGE_LIVE  | STAGE_PAUSE | STAGE_PAUSED
#define FULL_NONLIVE STAGE_START | STAGE_INIT | STAGE_PAUSE | STAGE_PAUSED | STAGE_STOPCOPY

struct emu {
    char *name;
    char **startup;
    char *waitfor;
    unsigned int waitfor_size;
    enum protocol proto;
    int enabled;

    int live_check;

    int exp_total;

    em_client_t *client;
    int stream;

    enum state status;
    char *result;
    struct argument *extra;

    uint64_t part_sent;
    uint64_t sent;
    uint64_t remaining;
    int iter;
};

#define CONTROL_PATH "/var/xen/%s/%d/control"

#define XENOPSD_TIMEOUT 120
#define XENOPSD_MSG_SIZE 128      /* maximum size of a message */
#define XENOPSD_RESTORE_MSG "restore:"
#define XENOPSD_ACK_MSG "done"

#define CMD_START_TIMEOUT 30
#define CMD_START_RBUF_LEN 128

/* xenopsd state */
static int xenopsd_in = -1;       /* xenopsd read fd */
static int xenopsd_out = -1;      /* xenopsd write fd */
static bool xenopsd_needs_ack;    /* true if we're expecting an ACK message */
static char xenopsd_rbuf[XENOPSD_MSG_SIZE];  /* receive buffer */
static int xenopsd_nbytes;        /* number of bytes of data in xenopsd_rbuf */

/* manager state */
static int domid = -1;
static bool live_migrate;
static int last_progress = -1;
static enum operation_mode operation_mode = op_invalid;

char *xenguest_args[] = {
    "/usr/libexec/xen/bin/xenguest",
    "-debug",
    "-domid", "%d",
    "-controloutfd", "2",
    "-controlinfd", "0",
    "-mode", "listen",
    NULL,
};

#define num_emus 3
struct emu emus[num_emus] = {
/*   name,       startup,       waitfor,   waitfor_size, proto, enabled,*/
    {"xenguest", xenguest_args, "Ready\n", 6,            emp,   (FULL_LIVE | STAGE_ENABLED),
/*   live_check, exp_total, client, stream, status,   result, extra, part_sent, sent, remaining, iter */
     true,       1000000,   NULL,   0,      not_done, NULL,   NULL,  0,         0,    0,         -1},
    {"vgpu",     NULL,          NULL,      0,            emp,   FULL_LIVE,
     false ,     100000,    NULL,   0,      not_done, NULL,   NULL,  0,         0,    0,         -1},
    {"qemu",     NULL,          NULL,      0,            qmp,   FULL_NONLIVE,
     false,      10,        NULL,   0,      not_done, NULL,   NULL,  0,         0,    0,         -1}
};

/* Forward declarations */

static int restore_emu(struct emu *emu);
static struct emu *find_emu_by_name(const char *name);

/* Functions for communicating with xenopsd */

/*
 * Read from xenopsd into an internal buffer. @timeout specifies the timeout
 * for the read in seconds.
 * @return -ETIME if a timeout occurs. -ENOSPC if there is no space remaining
 * in the buffer. -errno if any other error occurs. 0 if xenopsd
 * closes the connection. Otherwise returns the number of bytes read.
 */
static int xenopsd_read(int timeout)
{
    ssize_t ret;

    assert(xenopsd_nbytes <= XENOPSD_MSG_SIZE);

    if (xenopsd_nbytes == XENOPSD_MSG_SIZE)
        return -ENOSPC;

    ret = read_tlimit(xenopsd_in, xenopsd_rbuf + xenopsd_nbytes,
                      XENOPSD_MSG_SIZE - xenopsd_nbytes, timeout);
    if (ret > 0)
        xenopsd_nbytes += ret;

    return ret;
}

/*
 * Process a message, @msg, from xenopsd and perform actions depending on our
 * internal state.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_process_message(const char *msg)
{
    log_info("Processing '%s'", msg);

    if (!strcmp(msg, XENOPSD_ACK_MSG)) {
        if (!xenopsd_needs_ack) {
            log_err("Unexpected ACK received from xenopsd");
            return -EINVAL;
        }
        xenopsd_needs_ack = false;
        return 0;
    } else if (!strncmp(msg, XENOPSD_RESTORE_MSG, strlen(XENOPSD_RESTORE_MSG))) {
        struct emu *emu;

        msg += strlen(XENOPSD_RESTORE_MSG);

        emu = find_emu_by_name(msg);
        if (!emu) {
            log_err("Did do not know '%s'", msg);
            return -EINVAL;
        }

        return restore_emu(emu);
    }

    log_err("Unexpected message from xenopsd: %s", msg);
    return -EINVAL;
}

/*
 * Process any messages from xenopsd in the internal buffer.
 * @return The number of messages processed on success. -errno on failure.
 */
static int xenopsd_process(void)
{
    int processed = 0;
    int rc = 0;
    char *ptr, *endl;

    log_info("Process xenopsd read buffer: '%.*s'",
             xenopsd_nbytes, xenopsd_rbuf);

    ptr = xenopsd_rbuf;
    while (xenopsd_nbytes) {
        endl = memchr(ptr, '\n', xenopsd_nbytes);
        if (!endl) {
            if (xenopsd_nbytes == XENOPSD_MSG_SIZE)
                return -EMSGSIZE;
            break;
        }

        *endl = '\0';
        rc = xenopsd_process_message(ptr);
        xenopsd_nbytes -= endl - ptr + 1;
        ptr = endl + 1;
        if (rc < 0)
            break;
        processed++;
    }

    memmove(xenopsd_rbuf, ptr, xenopsd_nbytes);

    return rc ? rc : processed;
}

/*
 * Send @msg to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_message(const char *msg)
{
    int rc;

    log_info("Send '%s' to xenopsd", msg);

    rc = write_all(xenopsd_out, msg, strlen(msg));
    if (rc)
        log_err("Failed to write to xenopsd %d, %s", -rc, strerror(-rc));

    return rc;
}

/*
 * Inform xenopsd about progress of the operation.
 * @progress A value between 0 and 100 inclusive.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_progress(int progress)
{
    char buf[XENOPSD_MSG_SIZE];
    int rc;

    rc = snprintf(buf, XENOPSD_MSG_SIZE, "info:\\b\\b\\b\\b%d\n", progress);
    if (rc < 0)
        return -errno;

    return xenopsd_send_message(buf);
}

/*
 * Send a message to xenopsd and wait for the ACK.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_message_with_ack(const char *msg)
{
    int rc;

    rc = xenopsd_send_message(msg);
    if (rc)
        return rc;

    xenopsd_needs_ack = true;

    /*
     * Wait for an ACK by repeating until a message is processed or an
     * error occurs.
     */
    do {
        rc = xenopsd_read(XENOPSD_TIMEOUT);
        if (rc == 0) {
            log_err("Unexpected EOF on xenopsd control fd\n");
            return -EPIPE;
        } else if (rc < 0) {
            log_err("xenopsd read error: %d, %s\n", -rc, strerror(-rc));
            return rc;
        }

        rc = xenopsd_process();
    } while (rc >= 0 && xenopsd_needs_ack);

    return (rc < 0) ? rc : 0;
}

/*
 * Send the suspend message to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_suspend(void)
{
    return xenopsd_send_message_with_ack("suspend:\n");
}

/*
 * Send the prepare message for @emu to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_prepare(const struct emu *emu)
{
    char buf[XENOPSD_MSG_SIZE];
    int rc;

    rc = snprintf(buf, XENOPSD_MSG_SIZE, "prepare:%s\n", emu->name);
    if (rc < 0)
        return -errno;

    return xenopsd_send_message_with_ack(buf);
}

/*
 * Notify xenopsd that @emu is 'all done' along its result, if available.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_result(const struct emu *emu)
{
    char buf[XENOPSD_MSG_SIZE];
    int rc;

    if (emu->result)
        rc = snprintf(buf, XENOPSD_MSG_SIZE, "result:%s %s\n",
                      emu->name, emu->result);
    else
        rc = snprintf(buf, XENOPSD_MSG_SIZE, "result:%s\n", emu->name);

    if (rc < 0)
        return -errno;

    return xenopsd_send_message(buf);
}

/*
 * Sends the 'all done' message to xenopsd after a save operation.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_final_result(void)
{
    return xenopsd_send_message("result:0 0\n");
}

/*
 * Sends @err as an error result to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_error_result(int err)
{
    char msg[XENOPSD_MSG_SIZE];
    int rc;

    rc = snprintf(msg, XENOPSD_MSG_SIZE, "error:error code %d\n", err);
    if (rc < 0)
        return -errno;

    return xenopsd_send_message(msg);
}

/* Functions for program startup. */

/*
 * Parses an integer from a string given by @str. Except for whitespace at the
 * start, the string may not have leading or trailing characters that do not
 * form part of the number. Exits with status 1 if an error occurs.
 */
static int parse_int(const char *str)
{
    char *end;
    long result;

    errno = 0;
    result = strtol(str, &end, 10);

    if (errno || *end || (int)result != result) {
        log_err("Cannot parse '%s' as a valid integer", str);
        exit(1);
    }

    return (int)result;
}

/*
 * Parses the argument for the -dm option, given by @arg.
 * The argument is of the form: <emu-name>[:<fd>]
 * @arg may be mutated. Exits with status 1 if an error occurs.
 */
static void parse_dm_arg(char *arg)
{
    struct emu *emu;
    char *param;

    param = strchr(arg, ':');
    if (param) {
        *param = '\0';
        param++;
    }

    emu = find_emu_by_name(arg);

    if (!emu) {
        log_err("Bad dm arg: '%s', '%s'", arg, param);
        exit(1);
    }

    emu->enabled |= STAGE_ENABLED;

    if (param) {
        switch (emu->proto) {
        case emp:
            emu->stream = parse_int(param);
            break;
        case qmp:
            abort();
            break;
        }
    }
}

/*
 * Parse program arguments given by @argc and @argv.
 * Exits with status 1 if an error occurs.
 */
static void parse_args(int argc, char *argv[])
{
    enum {
        arg_controlinfd,
        arg_controloutfd,
        arg_debuglog,
        arg_fd,
        arg_domid,
        arg_live,
        arg_dm,
        arg_mode,
        arg_xg_store_port,
        arg_xg_console_port,
        arg_fork,
        arg_supports
    };

    static const struct option args[] = {
        {"controlinfd",  required_argument, NULL,   arg_controlinfd},
        {"controloutfd", required_argument, NULL,   arg_controloutfd},
        {"debuglog",     required_argument, NULL,   arg_debuglog},
        {"fd",           required_argument, NULL,   arg_fd},
        {"domid",        required_argument, NULL,   arg_domid},
        {"live",         required_argument, NULL,   arg_live},
        {"dm",           required_argument, NULL,   arg_dm},
        {"mode",         required_argument, NULL,   arg_mode},
        {"store_port",   required_argument, NULL,   arg_xg_store_port},
        {"console_port", required_argument, NULL,   arg_xg_console_port},
        {"fork",         required_argument, NULL,   arg_fork},
        {"supports",     required_argument, NULL,   arg_supports},
        {NULL},
    };

    /* These mode names correspond with enum operation_mode. */
    static const char *mode_names[] = {
        "hvm_save",
        "save",
        "hvm_restore",
        "restore",
        NULL
    };

    static const char *supports_table[] = {
        "migration-v2",
        NULL
    };

    int c, rc;
    ssize_t idx;

    for(;;) {
        int arg_index = 0;

        c = getopt_long_only(argc, argv, "", args, &arg_index);
        if (c == -1)
            break;

        log_info("c=%d, arg_index=%d, optarg=%s", c, arg_index, optarg);

        switch (c) {
        case arg_controlinfd:
            xenopsd_in = parse_int(optarg);
            break;
        case arg_controloutfd:
            xenopsd_out = parse_int(optarg);
            break;
        case arg_debuglog:
            log_debug_set(!strcmp(optarg, "true"));
            break;
        case arg_fd:
            emus[0].stream = parse_int(optarg);
            break;
        case arg_domid:
            domid = parse_int(optarg);
            break;
        case arg_live:
            if (!strcmp(optarg, "true")) {
                live_migrate = true;
            } else if (strcmp(optarg, "false")) {
                log_err("Unknown live argument: '%s'", optarg);
                exit(1);
            }
            break;
        case arg_dm:
            parse_dm_arg(optarg);
            break;
        case arg_mode:
            idx = strindex(mode_names, optarg);
            if (idx < 0) {
                log_err("Unknown mode '%s'", optarg);
                exit(1);
            }
            operation_mode = idx;
            break;
        case arg_xg_store_port:
        case arg_xg_console_port:
            log_info("adding xenguest special option %s = %s",
                     args[arg_index].name, optarg);
            rc = argument_add(&emus[0].extra, args[arg_index].name, optarg);
            if (rc) {
                log_err("Error adding xenguest argument: %d, %s",
                        -rc, strerror(-rc));
                exit(1);
            }
            break;
        case arg_fork: /* ignore */
            break;
        case arg_supports:
            operation_mode = op_end;
            if (strindex(supports_table, optarg) >= 0)
                printf("true\n");
            else
                printf("false\n");
            break;
        default:
            log_err("Error parsing arguments");
            exit(1);
            break;
        }
    }

    if (optind < argc) {
        log_err("Unknown extra arguments");
        exit(1);
    }
}

/* Functions for emu-manager operation. */

/*
 * Return the emu whose name is @name.
 * @return A pointer to the given emu if found, otherwise NULL. The pointer
 * should not be freed.
 */
static struct emu *find_emu_by_name(const char *name)
{
    int i;

    for (i = 0; i < num_emus; i++) {
        if (!strcmp(emus[i].name, name))
            return &emus[i];
    }

    return NULL;
}

/* Given @command, a list of program arguments, substitute all parameterized
 * arguments. This modifies @command.
 * @return 0 on success. -errno on failure.
 */
static int substitute_args(char **command)
{
    while (*command) {
        if (!strcmp(*command, "%d")) {
            if (asprintf(command, "%d", domid) < 0)
                return -errno;
        }
        command++;
    }

    return 0;
}

/*
 * This prevents stdout being buffered for a child process. This is a hack.
 * Remove this code when xenguest is fixed to avoid buffering its output.
 */
static int setenv_nobuffs(void)
{
    clearenv();
    if ((putenv("LD_PRELOAD=/usr/libexec/coreutils/libstdbuf.so") != 0) ||
            (putenv ("_STDBUF_O=0") != 0)) {
        log_err("Failed to putenv\n");
        return -1;
    }
    return 0;
}

/*
 * Execute @command and wait for it to signal that it has started by
 * matching @waitfor_size bytes of its stdout against @waitfor.
 * @return 0 on success. -errno on failure.
 */
static int exec_command(char **command,
                        char *waitfor, unsigned int waitfor_size)
{
    int comm[2];
    pid_t pid;
    ssize_t ret;
    size_t nbytes = 0;
    char buf[CMD_START_RBUF_LEN];

    if (pipe(comm) == -1)
        return -errno;

    pid = fork();
    if (pid == -1) {
        close_retry(comm[0]);
        close_retry(comm[1]);
        return -errno;
    } else if (pid == 0) {
        int rc;

        while ((rc = dup2(comm[1], STDOUT_FILENO)) == -1 && (errno == EINTR))
            ;

        if (rc < 0)
            _exit(1);

        close_retry(comm[1]);
        close_retry(comm[0]);

        setenv_nobuffs();

        execvp(command[0], command);
        _exit(1);
    }

    close_retry(comm[1]);

    do {
        ret = read_tlimit(comm[0], buf + nbytes,
                          CMD_START_RBUF_LEN - nbytes, CMD_START_TIMEOUT);
        if (ret < 0) {
            goto out;
        } else if (ret == 0) {
            ret = -EPIPE;
            goto out;
        }
        nbytes += ret;

        if (nbytes == waitfor_size) {
            ret = !memcmp(buf, waitfor, waitfor_size) ? 0 : -EINVAL;
            goto out;
        }
    } while (nbytes < waitfor_size);

out:
    close_retry(comm[0]);
    return ret;
}

/*
 * Calculates the progress.
 * @return The current progress between 0 and 100 inclusive.
 */
static int calculate_done(void)
{
    int i;
    uint64_t expect = 0;
    uint64_t sent  = 0;

    for (i = 0; i < num_emus; i++) {
        if (!emus[i].enabled)
            continue;

        if (emus[i].iter >= 0) {
            sent += emus[i].sent;

            /*
             * Add only 80% of a partial update to compensate for dirty pages
             * that will need to be copied again later.
             */
            sent += (emus[i].part_sent - emus[i].sent) * 80 / 100;

            expect += emus[i].sent + emus[i].remaining;
        } else {
            expect += emus[i].exp_total;
            if (emus[i].status >= all_done)
                sent += emus[i].exp_total;
        }
    }

    return expect ? sent * 100 / expect : 0;
}

/*
 * Calculates the progress and sends it to xenopsd.
 * @return The current progress between 0 and 100 inclusive. -errno on failure.
 */
static int update_progress(void)
{
    int rc = 0;
    int progress = calculate_done();

    if (last_progress != progress) {
        rc = xenopsd_send_progress(progress);
        last_progress = progress;
    }
    return rc ? rc : progress;
}

/*
 * Process @event from em client @cli with data given by @data.
 * Calculate the updated progress and send it to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int emu_event_cb(em_client_t *cli, const char *event, json_object *data)
{
    struct emu *emu = cli->data;
    int64_t rem = -1;
    int64_t sent = -1;
    int iter = -1;

    if (strcmp(event, "MIGRATION")) {
        log_err("Unknown event type: %s", event);
        return -EINVAL;
    }

    json_object_object_foreach(data, key, val) {
        if (!strcmp(key, "status")) {
            if (json_object_get_type(val) == json_type_string) {
                const char *status = json_object_get_string(val);

                if (strcmp(status, "completed")) {
                    log_info("Error: emu %s status: %s", emu->name, status);
                    return -EINVAL;
                }
                emu->status = all_done;
            } else {
                log_err("Unexpected event data");
                return -EINVAL;
            }
        } else if (!strcmp(key, "result")) {
            if (json_object_get_type(val) == json_type_string) {
                emu->result = strdup(json_object_get_string(val));
                if (!emu->result)
                    return -ENOMEM;
            } else {
                log_err("Unexpected event data");
                return -EINVAL;
            }
        }  else if (json_object_get_type(val) == json_type_int) {
            if (!strcmp(key, "remaining")) {
                rem = json_object_get_int64(val);
            } else if (!strcmp(key, "sent")) {
                sent = json_object_get_int64(val);
            } else if (!strcmp(key, "iteration")) {
                iter = json_object_get_int(val);
            } else {
                log_err("Unexpected event data");
                return -EINVAL;
            }
        } else {
            log_err("Unexpected event data");
            return -EINVAL;
        }
    }

    if (rem >= 0 || iter >= 0) {
        int progress;
        bool ready = emu->status == live_done;

        /* remaining can be wrong - fix it up if it is. */
        if (rem == 0 && iter == 0)
            rem = -1;

        if (rem != -1) {
            emu->remaining = rem;
            emu->sent = sent;
            emu->iter = iter;
        }
        emu->part_sent = sent;

        progress = update_progress();
        if (progress < 0)
            return progress;

        log_info("Event for %s: rem %"PRId64", sent %"PRId64", iter %d, %s. Progress = %d",
                 emu->name, rem, sent, iter,
                 ready ? "waiting" : "not waiting", progress);
        if ((iter > 0) && (rem < 50 || iter >= 4) && !ready) {
            log_info("emu %s: live done", emu->name);
            emu->status = live_done;
        }
    }

    return 0;
}

/*
 * Start all emus that need to be started.
 * @return 0 on success. -errno on failure.
 */
static int startup_emus(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].startup) {
            log_info("Starting %s\n", emus[i].name);

            rc = substitute_args(emus[i].startup);
            if (rc) {
                log_err("Error substituting arguments for %s: %d, %s",
                        emus[i].name, -rc, strerror(-rc));
                return rc;
            }

            rc = exec_command(emus[i].startup,
                              emus[i].waitfor, emus[i].waitfor_size);
            if (rc) {
                log_err("Error starting %s: %d, %s",
                        emus[i].name, -rc, strerror(-rc));
                return rc;
            }
        }
    }
    return 0;
}

/*
 * Open a connection to @emu.
 * @return 0 on success. -errno on failure.
 */
static int connect_emu(struct emu *emu)
{
    char path[64];
    int rc;

    rc = snprintf(path, sizeof(path), CONTROL_PATH, emu->name, domid);
    if (rc < 0)
        return -errno;

    rc = em_client_alloc(&emu->client, emu_event_cb, emu);
    if (rc)
        return rc;

    return em_client_connect(emu->client, path);
}

/*
 * Connect to all emus.
 * @return 0 on success. -errno on failure.
 */
static int connect_emus(void)
{
    int i;
    int rc;
    struct emu *emu;

    for (i = 0; i < num_emus; i++) {
        emu = &emus[i];
        if (!emu->enabled)
            continue;

        switch (emu->proto) {
        case emp:
            if ((rc = connect_emu(emu))) {
                log_err("Failed to connect to %s: %d, %s",
                        emu->name, -rc, strerror(-rc));
                return rc;
            }
            break;
        case qmp:
            abort();
            break;
        }
    }
    return 0;
}

/*
 * Send migrate_init to each emu and any extra arguments required.
 * @return 0 on success. -errno on failure.
 */
static int init_emus(void)
{
    int i;
    int rc;
    struct emu *emu;

    for (i = 0; i < num_emus; i++) {
        emu = &emus[i];
        if (!(emu->enabled && STAGE_INIT))
            continue;

        switch (emu->proto) {
        case emp:
            rc = em_client_send_cmd_fd(emu->client, cmd_migrate_init,
                                       emu->stream);
            if (rc)
                return rc;

            if (emu->extra) {
                rc = em_client_send_cmd_args(emu->client, cmd_set_args,
                                             emu->extra);
                if (rc)
                    return rc;
            }

            break;
        case qmp:
            abort();
            break;
        }
    }
    return 0;
}

/*
 * Enable dirty page tracking and progress reporting for live emus.
 * @return 0 on success. -errno on failure.
 */
static int request_track_emus(void)
{
    int i;
    int rc;
    struct emu *emu;

    for (i = 0; i < num_emus; i++) {
        emu = &emus[i];
        if (!(emu->enabled && STAGE_LIVE))
            continue;

        switch (emu->proto) {
        case emp:
            rc = em_client_send_cmd(emu->client, cmd_track_dirty);
            if (rc)
                return rc;

            rc = em_client_send_cmd(emu->client, cmd_migrate_progress);
            if (rc)
                return rc;

            break;
        case qmp:
            abort();
            break;
        }
    }
    return 0;
}

/*
 * Send cmd_restore to @emu.
 * @return 0 on success. -errno on failure.
 */
static int restore_emu(struct emu *emu)
{
    int rc;

    if (emu->status != not_done) {
        log_err("Request to restore emu '%s' already in progress", emu->name);
        return -EINVAL;
    }

    log_info("restore %s", emu->name);

    rc = em_client_send_cmd(emu->client, cmd_restore);
    if (rc < 0) {
        log_err("Failed to start restore for %s\n", emu->name);
        return rc;
    }

    emu->status = started;

    return 0;
}

/*
 * Start migration for each live emu.
 * @return 0 on success. -errno on failure.
 */
static int migrate_live_emus(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_LIVE))
            continue;

        rc = xenopsd_send_prepare(&emus[i]);
        if (rc < 0) {
            log_err("Failed to prepare stream for %s: %d, %s\n",
                    emus[i].name, -rc, strerror(-rc));
            return rc;
        }

        log_info("Migrate live %d: %s", i, emus[i].name);
        rc = em_client_send_cmd(emus[i].client, cmd_migrate_live);
        if (rc)
            return rc;
    }

    return 0;
}

/*
 * Tell all emus to pause.
 * @return 0 on success. -errno on failure.
 */
static int pause_emus(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_PAUSED))
            continue;

        rc = em_client_send_cmd(emus[i].client, cmd_migrate_paused);
        if (rc)
            return rc;
    }

    return 0;
}

/*
 * Close connections to all connected emus and tell any emus we've started to
 * quit. This will not return immediately if an error is received. Instead, it
 * will perform all the work and return the first error code.
 * @return 0 on success. -errno on failure.
 */
static int migrate_end(void)
{
    int i;
    int ret;
    int rc = 0;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].client) {
            if (emus[i].client->fd >= 0 && emus[i].startup) {
                ret = em_client_send_cmd(emus[i].client, cmd_quit);
                if (ret && !rc)
                    rc = ret;
            }
            ret = em_client_free(emus[i].client);
            if (ret && !rc)
                rc = ret;
        }
        if (emus[i].stream) {
            ret = close_retry(emus[i].stream);
            if (ret && !rc)
                rc = ret;
        }
    }
    return rc;
}

/*
 * Wait for an event to occur or process existing data.
 * @return 0 on success. -errno on failure.
 */
static int wait_for_event(void)
{
    int i;
    int rc, r;
    fd_set rfds;
    fd_set wfds;
    fd_set xfds;
    int max_fd = xenopsd_in;
    struct timeval tv = {30, 0};  /* 30 second timeout */

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    FD_SET(xenopsd_in, &rfds);

    for (i = 0; i < num_emus; i++) {
        int fd;

        if (!emus[i].enabled)
            continue;

        fd = emus[i].client->fd;
        FD_SET(fd, &rfds);
        if (fd > max_fd)
            max_fd = fd;
    }

    rc = select(max_fd + 1, &rfds, &wfds, &xfds, &tv);

    if (rc > 0) {
        if (FD_ISSET(xenopsd_in, &rfds)) {
            r = xenopsd_read(0);
            if (r == 0) {
                log_err("Unexpected EOF on xenopsd control fd\n");
                return -EPIPE;
            } else if (r < 0) {
                log_err("xenospd read error: %d, %s\n", -r, strerror(-r));
                return r;
            }
            r = xenopsd_process();
            log_info("control message rc = %d", r);
            if (r < 0 )
                return r;
        }

        for (i = 0; i < num_emus; i++) {
            if (emus[i].enabled && FD_ISSET(emus[i].client->fd, &rfds)) {
                r = em_client_read(emus[i].client, 0);
                if (r == 0) {
                    log_err("Unexpected EOF on emu socket\n");
                    return -EPIPE;
                } else if (r < 0) {
                    log_err("emu read error: %d, %s\n", -r, strerror(-r));
                    return r;
                }
                r = em_client_process(emus[i].client);
                log_info("em client message rc = %d", r);
                if (r < 0 )
                    return r;
            }
        }

        rc = 0;
    } else if (rc == 0) {
        return -ETIME;
    }

    return rc;
}

/* Returns true if @emu is live and has not yet finished. False otherwise. */
static bool check_live_not_finished(const struct emu *emu)
{
    return (emu->enabled & STAGE_LIVE) && emu->status != all_done;
}

/* Returns true if @emu is live and has not yet started. False otherwise. */
static bool check_live_not_started(const struct emu *emu)
{
    return (emu->enabled & STAGE_LIVE) && emu->status == not_done;
}

/*
 * Wait for @check to return false for every emu.
 * @return 0 on success. -errno on failure.
 */
static int wait_on_condition(bool (*check)(const struct emu *emu))
{
    int i;
    int rc;
    int remaining;

    for (;;) {
        remaining = 0;
        for (i = 0; i < num_emus; i++) {
            if (check(&emus[i]))
                remaining++;
        }

        if (remaining == 0)
            break;

        rc = wait_for_event();
        if (rc < 0 && rc != -ETIME) {
            log_err("Error waiting for events: %d, %s",
                    -rc, strerror(-rc));
            return -rc;
        }
        update_progress();
    }

    return 0;
}

/*
 * Sequentially save each nonlive emu and wait for completion.
 * @return 0 on success. -errno on failure.
 */
static int save_nonlive_one_by_one(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_STOPCOPY))
            continue;

        rc = xenopsd_send_prepare(&emus[i]);
        if (rc < 0)
            return rc;

        rc = em_client_send_cmd(emus[i].client, cmd_migrate_nonlive);
        if (rc < 0)
            return rc;

        while (emus[i].status != all_done) {
            rc = wait_for_event();
            if (rc < 0 && rc != -ETIME) {
                log_err("Error waiting for events: %d, %s",
                        -rc, strerror(-rc));
                return -rc;
            }

            update_progress();
        }

        if (emus[i].stream)
            syncfs(emus[i].stream);
    }

    return 0;
}

/* Set up the enabled stages for each emu. */
static void configure_emus(void)
{
    int i;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].enabled & STAGE_ENABLED) {
            log_info("emu %s enabled", emus[i].name);
            if (!live_migrate)
                emus[i].enabled = (emus[i].enabled | STAGE_STOPCOPY ) & ~STAGE_LIVE;
        } else {
            emus[i].enabled = 0;
        }
    }
}

/*
 * Perform the load operation. Reports the final result or an error to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int operation_load(void)
{
    int rc, end_rc;
    int i;
    int remaining = 0;

    configure_emus();

    rc = startup_emus();
    if (rc)
        goto out;

    rc = connect_emus();
    if (rc)
        goto out;

    rc = init_emus();
    if (rc)
        goto out;

    log_info("Wait for completion");
    /* Count number of emus we need to wait for. */
    for (i = 0; i < num_emus; i++) {
        if (emus[i].enabled)
            remaining++;
    }
    while (remaining) {
        rc = wait_for_event();
        if (rc < 0 && rc != -ETIME) {
            log_err("Error waiting for events: %d, %s",
                    -rc, strerror(-rc));
            goto out;
        }

        for (i = 0; i < num_emus; i++) {
            if (emus[i].status == all_done) {
                log_info("emu %s complete", emus[i].name);
                xenopsd_send_result(&emus[i]);
                emus[i].status = result_sent;
                remaining--;
            }
        }
    }
    rc = 0;

out:
    end_rc = migrate_end();
    if (end_rc) {
        log_err("Error calling migrate_end(): %d, %s",
                -end_rc, strerror(-end_rc));
        if (!rc)
            rc = end_rc;
    }

    if (rc) {
        end_rc = xenopsd_send_error_result(rc);

        if (end_rc)
            log_err("sending error to xenopsd failed: %d, %s",
                    -end_rc, strerror(-end_rc));
    }

    return rc;
}

/*
 * Tell all emus to abort. This will not return immediately if an error is
 * received. Instead, it will tell all the emus to abort and return the
 * first error code.
 * @return 0 on success. -errno on failure.
 */
static int migrate_abort(void)
{
    int i;
    int rc = 0;
    int ret;

    log_info("Tell all emus to abort");

    for (i = 0; i < num_emus; i++) {
        if (emus[i].enabled) {
            switch (emus[i].proto) {
            case emp:
                if (emus[i].client && emus[i].client->fd >= 0) {
                    ret = em_client_send_cmd(emus[i].client, cmd_migrate_abort);
                    if (ret && !rc)
                        rc = ret;
                }
            case qmp:
                abort();
                break;
            }
        }
    }

    return rc;
}

/*
 * Perform the save operation. Reports the final result or an error to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int operation_save(void)
{
    int rc;
    int end_rc = 0;
    bool can_abort = false;

    configure_emus();

    rc = startup_emus();
    if (rc)
        goto out;

    can_abort = true;

    rc = connect_emus();
    if (rc)
        goto out;

    rc = init_emus();
    if (rc)
        goto out;

    if (live_migrate) {
        rc = request_track_emus();
        if (rc)
            goto out;

        rc = migrate_live_emus();
        if (rc)
            goto out;

        rc = wait_on_condition(check_live_not_started);
        if (rc)
            goto out;
    }

    can_abort = false;

    rc = xenopsd_send_suspend();
    if (rc)
        goto out;

    rc = pause_emus();
    if (rc)
        goto out;

    rc = wait_on_condition(check_live_not_finished);
    if (rc)
        goto out;

    rc = save_nonlive_one_by_one();
    if (rc)
        goto out;

    rc = xenopsd_send_final_result();

out:
    if (rc && can_abort) {
        end_rc = migrate_abort();
        if (end_rc)
            log_err("Error calling migrate_abort(): %d, %s",
                    -end_rc, strerror(-end_rc));
    }

    if (!end_rc) {
        end_rc = migrate_end();
        if (end_rc) {
            log_err("Error calling migrate_end(): %d, %s",
                    -end_rc, strerror(-end_rc));
            if (!rc)
                rc = end_rc;
        }
    }

    if (rc) {
        end_rc = xenopsd_send_error_result(rc);
        if (end_rc)
            log_err("sending error to xenopsd failed: %d, %s",
                    -end_rc, strerror(-end_rc));
    }

    return rc;
}

/*
 * Exits with code 0 on success, 1 if an error occurs during argument parsing
 * or emu-manager initialization, 2 if an error occurs during operation.
 */
int main(int argc, char *argv[])
{
    int rc;
    struct sigaction sa;
    char *ident;

    parse_args(argc, argv);

    if (operation_mode == op_end)
        return 0;

    if (operation_mode == op_invalid)
        return 1;

    if (asprintf(&ident, "%s-%d", basename(argv[0]), domid) > 0)
        openlog(ident, LOG_PID, LOG_DAEMON);

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL)) {
        log_err("Error ignoring SIGPIPE %d, %s", errno, strerror(errno));
        return 1;
    }

    log_info("Starting...");
    log_debug("YYY...");
    log_info("xenopsd control fds (%d, %d)", xenopsd_in, xenopsd_out);

    switch (operation_mode) {
    case op_pvsave:
        rc = argument_add(&emus[0].extra, "pv", "true");
        if (rc) {
            log_err("Error adding pv argument: %d, %s", -rc, strerror(-rc));
            return 1;
        }
        /* fall though */
    case op_save:
        return operation_save() ? 2 : 0;
    case op_pvrestore:
        rc = argument_add(&emus[0].extra, "pv", "true");
        if (rc) {
            log_err("Error adding pv argument: %d, %s", -rc, strerror(-rc));
            return 1;
        }
        /* fall though */
    case op_restore:
        return operation_load() ? 2 : 0;
    default:
        log_err("Invalid mode");
        return 1;
    }
}
