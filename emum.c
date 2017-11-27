#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <stdlib.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <termios.h>
#include <signal.h>
#include "em-client.h"
#include "lib.h"
#include <syslog.h>

#define CONTROL_PATH "/var/xen/%s/%d/control"

#include <poll.h>
#include <stdbool.h>

enum operation_mode {
   op_invalid = -1,
   op_save    = 0,
   op_pvsave,
   op_restore,
   op_pvrestore,
   op_end
};

int gDomid  = 0;
static bool gLive;
int gLastUpdateP = -1;
enum operation_mode gMode=op_invalid;

/* xenopsd data and definitions */
#define XENOPSD_MSG_SIZE 128      /* maximum size of a message */
#define RESTORE_MSG "restore:"
#define ACK_MSG "done"

static int xenopsd_in = -1;
static int xenopsd_out = -1;
static bool xenopsd_needs_ack;    /* true if we're expecting an ACK message */
static char xenopsd_rbuf[XENOPSD_MSG_SIZE];  /* receive buffer */
static int xenopsd_nbytes;        /* number of bytes of data in xenopsd_rbuf */

enum protocol {
emp,
qmp
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

#define XENOPSD_TIMOUT (60 * 2)

#define CMD_START_TIMEOUT 30
#define CMD_START_RBUF_LEN 128

#define STAGE_ENABLED  (1 << stage_enabled)
#define STAGE_START    (1 << stage_start)
#define STAGE_INIT     (1 << stage_init)
#define STAGE_LIVE     (1 << stage_live)
#define STAGE_PAUSE    (1 << stage_pause)
#define STAGE_PAUSED   (1 << stage_paused)
#define STAGE_STOPCOPY (1 << stage_stopcopy)

#define FULL_LIVE    STAGE_START | STAGE_INIT | STAGE_LIVE  | STAGE_PAUSE | STAGE_PAUSED
#define FULL_NONLIVE STAGE_START | STAGE_INIT | STAGE_PAUSE | STAGE_PAUSED | STAGE_STOPCOPY

enum state {
    not_done=0,
    started,
    live_done,
    all_done,
    result_sent
};


struct data_stats {
   uint64_t part_sent;
   uint64_t sent;
   uint64_t remaining;
   int iter;
};

struct emu {
    char *name;
    char **startup;
    char *waitfor;
    unsigned int waitfor_size;
    enum protocol proto;
    int enabled;

    int live_check;

    int exp_total;

    emu_socket_t* sock;
    int stream;

    enum state status;
    char* result;
    int error;
    struct argument *extra;
    struct data_stats* data_stats;
};

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
/*   name,       startup,       waitfor,   waitfor_size, proto, enabled,                     live_check, exp_total, sock, stream, status,   result, error, extra, data_stats */
    {"xenguest", xenguest_args, "Ready\n", 6,            emp,   (FULL_LIVE | STAGE_ENABLED), true,       1000000,   NULL, 0,      not_done, NULL,   0,     NULL,  NULL},
    {"vgpu",     NULL,          NULL,      0,            emp,   FULL_LIVE,                   false ,     100000,    NULL, 0,      not_done, NULL,   0,     NULL,  NULL},
    {"qemu",     NULL,          NULL,      0,            qmp,   FULL_NONLIVE,                false,      10,        NULL, 0,      not_done, NULL,   0,     NULL,  NULL}
};

#define emu_info(args...) syslog(LOG_DAEMON|LOG_INFO, args)
#define emu_err(args...) syslog(LOG_DAEMON|LOG_ERR, args)

static int restore_emu(struct emu *emu);

static int calculate_done(void)
{
    int i;

    uint64_t total_expect = 0;
    uint64_t total_sent  = 0;
    uint64_t perc;

    for (i=0; i< num_emus; i++) {
       if (emus[i].enabled) {
           if (emus[i].data_stats) {
               total_sent += emus[i].data_stats->sent;

               /* Add 80% of partial update, to compinsate for lack cosideration of dirtying of pages */
               total_sent += ((emus[i].data_stats->part_sent - emus[i].data_stats->sent) * 80) / 100;

               total_expect += emus[i].data_stats->sent + emus[i].data_stats->remaining;
           } else {
              total_expect += emus[i].exp_total;
              if (emus[i].status >= all_done)
                  total_sent += emus[i].exp_total;
           }
       }
   }

   perc = (total_expect)?(total_sent * 100) / total_expect:0;
   return (uint) perc;
}

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

static int str_lookup(const char* table[], char cmp[])
{
    int i;
    for (i=0; table[i]; i++) {
        if (strcmp(table[i], cmp)==0)
           return i;
    }
    return -1;
}

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
    emu_info("Processing '%s'", msg);

    if (!strcmp(msg, ACK_MSG)) {
        if (!xenopsd_needs_ack) {
            emu_err("Unexpected ACK received from xenopsd");
            return -EINVAL;
        }
        xenopsd_needs_ack = false;
        return 0;
    } else if (!strncmp(msg, RESTORE_MSG, strlen(RESTORE_MSG))) {
        struct emu *emu;

        msg += strlen(RESTORE_MSG);

        emu = find_emu_by_name(msg);
        if (!emu) {
            emu_err("Did do not know '%s'", msg);
            return -EINVAL;
        }

        return restore_emu(emu);
    }

    emu_err("Unexpected message from xenopsd: %s", msg);
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

    emu_info("Process xenopsd read buffer: '%.*s'",
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

    emu_info("Send '%s' to xenopsd", msg);

    rc = write_all(xenopsd_out, msg, strlen(msg));
    if (rc)
        emu_err("Failed to write to xenopsd %d, %s", -rc, strerror(-rc));

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

static int update_progress(void)
{

   int progress = calculate_done();

   if (gLastUpdateP != progress) {
       xenopsd_send_progress(progress);
       gLastUpdateP = progress;
   }
   return progress;
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
        rc = xenopsd_read(XENOPSD_TIMOUT);
        if (rc == 0) {
            emu_err("Unexpected EOF on xenopsd control fd\n");
            return -EPIPE;
        } else if (rc < 0) {
            emu_err("xenopsd read error: %d, %s\n", -rc, strerror(-rc));
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
        emu_err("Cannot parse '%s' as a valid integer", str);
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
        emu_err("Bad dm arg: '%s', '%s'", arg, param);
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

    for(;;) {
        int arg_index = 0;

        c = getopt_long_only(argc, argv, "", args, &arg_index);
        if (c == -1)
            break;

        emu_info("c=%d, arg_index=%d, optarg=%s", c, arg_index, optarg);

        switch (c) {
            case arg_controlinfd:
                xenopsd_in = parse_int(optarg);
                break;
            case arg_controloutfd:
                xenopsd_out = parse_int(optarg);
                break;
            case arg_debuglog:
                break;
            case arg_fd:
                emus[0].stream = parse_int(optarg);
                break;
            case arg_domid:
                gDomid = parse_int(optarg);
                break;
            case arg_live:
                if (!strcmp(optarg, "true")) {
                    gLive = true;
                } else if (strcmp(optarg, "false")) {
                    emu_err("Unknown live argument: '%s'", optarg);
                    exit(1);
                }
                break;
            case arg_dm:
                parse_dm_arg(optarg);
                break;
            case arg_mode:
                gMode = str_lookup(mode_names, optarg);
                if (gMode < 0) {
                    emu_err("Unknown mode '%s'", optarg);
                    exit(1);
                }
                break;
            case arg_xg_store_port:
            case arg_xg_console_port:
                emu_info("adding xenguest special option %s = %s",
                         args[arg_index].name, optarg);
                rc = argument_add(&emus[0].extra, args[arg_index].name, optarg);
                if (rc) {
                    emu_err("Error adding xenguest argument: %d, %s",
                            -rc, strerror(-rc));
                    exit(1);
                }
                break;
            case arg_fork: /* ignore */
                break;
            case arg_supports:
                gMode = op_end;
                if (str_lookup(supports_table, optarg) >= 0)
                    printf("true\n");
                else
                    printf("false\n");
                break;
            default:
                emu_err("Error parsing arguments");
                exit(1);
                break;
        }
    }

    if (optind < argc) {
        emu_err("Unknown extra arguments");
        exit(1);
    }
}

EMP_COMMANDS(commands);

/* Given @command, a list of program arguments, substitute all parameterized
 * arguments. This modifies @command.
 * @return 0 on success. -errno on failure.
 */
static int substitute_args(char **command)
{
   while (*command) {
       if (!strcmp(*command, "%d")) {
           if (asprintf(command, "%d", gDomid) < 0)
               return -errno;
       }
       command++;
   }

   return 0;
}

/* This prevents stdout being buffered */
static int setenv_nobuffs(void)
{
    clearenv();
    if ((putenv("LD_PRELOAD=/usr/libexec/coreutils/libstdbuf.so")!=0) ||
        (putenv ("_STDBUF_O=0") != 0)) {
        emu_err("Failed to putenv\n");
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
        close(comm[0]);
        close(comm[1]);
        return -errno;
    } else if (pid == 0) {
        int rc;

        while ((rc = dup2(comm[1], STDOUT_FILENO)) == -1 && (errno == EINTR)) {}

        if (rc < 0)
            _exit(1);

        close(comm[1]);
        close(comm[0]);

        setenv_nobuffs();

        execvp(command[0], command);
        _exit(1);
    }

    close(comm[1]);

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
    close(comm[0]);
    return ret;
}

static int process_status_stats(struct emu* emu, int iter, int sent, int rem)
{
   int ready = (emu->status == live_done);
   int progress;

   /* fudge - remaining can be a wrong. */
   if ((iter==0) && (rem == 0))
         rem = -1;

   if (emu->data_stats == NULL) {
      emu->data_stats = malloc(sizeof( struct data_stats));
      if (emu->data_stats == NULL) {
           emu_err("Failed to alloc data_stats for %s", emu->name);
      } else {
           emu->data_stats->remaining = -1;
      }
   }
   if (emu->data_stats != NULL) {

          if (rem != -1) {
              emu->data_stats->remaining = rem;
              emu->data_stats->sent = sent;
              emu->data_stats->iter = iter;
              emu->data_stats->part_sent = sent;
          } else {
              emu->data_stats->part_sent = sent;
          }
   }
   progress =  update_progress();

   emu_info("for %s:rem %d, iter %d, send %d %s.  Tot=%d",emu->name, rem, iter, sent, (ready)?" Waiting":"", progress);
   if ((iter>0) && (rem < 50 || iter >= 4) && !ready) {
       emu_info("criteria met - signal ready");
       emu->status= live_done;
   }

   return 0;
}

/* where events are parsed */
static int emu_callback(json_object *jobj, emu_socket_t* sock)
{
   struct emu* emu = (struct emu*) sock->data;
   int r;

   json_object *event=NULL;
   json_object *data=NULL;

   json_object_object_foreach(jobj, key, val) {
      if (strcmp(key, "data") == 0) {
         r = json_object_get_type(val);
         if (r == json_type_object)
             data=val;
         else
             emu_err("Data must be of type object - got %d", r);
      }
      if (strcmp(key, "event") == 0) {
         r = json_object_get_type(val);
         if (r == json_type_string)
             event=val;
         else
             emu_err("Events must be of type string - got %d", r);
      }
   }

   if (event && data) {
        const char* ev_str=NULL;
        ev_str= json_object_get_string(event);

        if (strcmp(ev_str,"MIGRATION")==0) {
           int rem = -1;
           int iter = -1;
           int sent = -1;

           json_object_object_foreach(data, key, val) {
             if (strcmp(key, "status")==0) {
                  if (json_object_get_type(val) == json_type_string) {
                      const char * res = json_object_get_string(val);

                      if (strcmp(res, "completed") != 0) {
                            emu->error = 1;
                            emu_info("emu %s status %s!", emu->name, res);
                      } else
                            emu_info("emu %s status Finished!", emu->name);
                      emu->status = all_done;
                  } else {
                      emu_err("expected string for status");
                  }
             } else if (strcmp(key, "result")==0) {
                  if (json_object_get_type(val) == json_type_string) {
                      const char * res = json_object_get_string(val);
                      emu->result = strdup(res);
                      if (emu->result == NULL)
                         emu_err("Failed to alloc result");
                  } else {
                      emu_err("expected string for result");
                  }

             }  else if (json_object_get_type(val) == json_type_int) {
               int v = json_object_get_int(val);

               if (strcmp(key, "remaining")==0) {
                   rem = v;
               } else if (strcmp(key, "iteration")==0) {
                    iter = v;
               }
               else if (strcmp(key, "sent")==0) { 
                    sent = v;
               } else {
                   emu_info("With %s, sent unexpected %s of value %d", emu->name, key, v);
               };
             } else
                   emu_info("Unexpected magrtion data %s", key);
             } // for
             if (rem >=0 || iter >= 0) {
                 process_status_stats(emu, iter, sent, rem);
             }

        } else
        {
         emu_info("With %s, Unkown event type '%s'. Ignoring.", emu->name, ev_str);
        }
   } else {
      emu_err("Called on something not an event");
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
            emu_info("Starting %s\n", emus[i].name);

            rc = substitute_args(emus[i].startup);
            if (rc) {
                emu_err("Error substituting arguments for %s: %d, %s",
                        emus[i].name, -rc, strerror(-rc));
                return rc;
            }

            rc = exec_command(emus[i].startup,
                              emus[i].waitfor, emus[i].waitfor_size);
            if (rc) {
                emu_err("Error starting %s: %d, %s",
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

    rc = snprintf(path, sizeof(path), CONTROL_PATH, emu->name, gDomid);
    if (rc < 0)
        return -errno;

    rc = em_socket_alloc(&emu->sock, emu_callback, emu);
    if (rc)
        return rc;

    return em_socket_connect(emu->sock, path);
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
                    emu_err("Failed to open socket for %s: %d, %s",
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
                rc = em_socke_send_cmd_fd(emu->sock, cmd_migrate_init,
                                          emu->stream);
                if (rc)
                    return rc;

                if (emu->extra) {
                    rc = em_socke_send_cmd_args(emu->sock, cmd_set_args,
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
                rc = em_socke_send_cmd(emu->sock, cmd_track_dirty);
                if (rc)
                    return rc;

                rc = em_socke_send_cmd(emu->sock, cmd_migrate_progress);
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
        emu_err("Request to restore emu '%s' already in progress", emu->name);
        return -EINVAL;
    }

    emu_info("restore %s", emu->name);

    rc = em_socke_send_cmd(emu->sock, cmd_restore);
    if (rc < 0) {
        emu_err("Failed to start restore for %s\n", emu->name);
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
            emu_err("Failed to prepare stream for %s: %d, %s\n",
                    emus[i].name, -rc, strerror(-rc));
            return rc;
        }

        emu_info("Migrate live %d: %s", i, emus[i].name);
        rc = em_socke_send_cmd(emus[i].sock, cmd_migrate_live);
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

        rc = em_socke_send_cmd(emus[i].sock, cmd_migrate_paused);
        if (rc)
            return rc;
    }

    return 0;
}

static int migrate_end(void)
{
   int fd;
   int i;

   for (i=0; i< num_emus; i++) {
      if (emus[i].sock) {

         fd = emus[i].sock->fd;
         if (fd) {
            if ( fd && emus[i].startup)
              em_socke_send_cmd(emus[i].sock,cmd_quit);
            em_socket_free(emus[i].sock);
         }
         free(emus[i].sock);
      }
      fd = emus[i].stream;
      if (fd)
          close(fd);
   }
   return 0;
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

        fd = emus[i].sock->fd;
        FD_SET(fd, &rfds);
        if (fd > max_fd)
            max_fd = fd;
    }

    rc = select(max_fd + 1, &rfds, &wfds, &xfds, &tv);

    if (rc > 0) {
        if (FD_ISSET(xenopsd_in, &rfds)) {
            r = xenopsd_read(0);
            if (r == 0) {
                emu_err("Unexpected EOF on xenopsd control fd\n");
                return -EPIPE;
            } else if (r < 0) {
                emu_err("xenospd read error: %d, %s\n", -r, strerror(-r));
                return r;
            }
            r = xenopsd_process();
            emu_info("control message rc = %d", r);
            if (r < 0 )
                return r;
        }

        for (i = 0; i < num_emus; i++) {
            if (emus[i].enabled && FD_ISSET(emus[i].sock->fd, &rfds)) {
                r = em_socket_read(emus[i].sock, 0);
                if (r == 0) {
                    emu_err("Unexpected EOF on emu socket\n");
                    return -EPIPE;
                } else if (r < 0) {
                    emu_err("emu read error: %d, %s\n", -r, strerror(-r));
                    return r;
                }
                r = em_socket_process(emus[i].sock);
                emu_info("emu socket message rc = %d", r);
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
            emu_err("Error waiting for events: %d, %s",
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

        rc = em_socke_send_cmd(emus[i].sock, cmd_migrate_nonlive);
        if (rc < 0)
            return rc;

        while (emus[i].status != all_done) {
            rc = wait_for_event();
            if (rc < 0 && rc != -ETIME) {
                emu_err("Error waiting for events: %d, %s",
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
            emu_info("emu %s enabled", emus[i].name);
            if (!gLive)
                emus[i].enabled = (emus[i].enabled | STAGE_STOPCOPY ) & ~STAGE_LIVE;
        } else {
            emus[i].enabled = 0;
        }
    }
}

static int operation_load(void)
{
   int r;
   int i;
   int remaining = 0;

   configure_emus();

   r = startup_emus();
   if (r)
       goto load_end;

   r = connect_emus();
   if (r)
       goto load_end;

   r = init_emus();
   if (r)
       goto load_end;

   emu_info("Wait for completion");
   /* Count number of emus we need to wait for. */
   for (i = 0; i < num_emus; i++) {
       if (emus[i].enabled)
           remaining++;
   }
   while (remaining) {
       r = wait_for_event();
       if (r < 0 && r != -ETIME) {
           emu_err("Error waiting for events: %d, %s",
                   -r, strerror(-r));
           goto load_end;
       }

       for (i = 0; i < num_emus; i++) {
           if (emus[i].status == all_done) {
               if (emus[i].error) {
                   r = -1;
                   emu_err("EMU failed.");
                   goto load_end;
               }
               xenopsd_send_result(&emus[i]);
               emu_info("emu %s complete", emus[i].name);
               emus[i].status = result_sent;
               remaining--;
           }
       }
   }
   r = 0;

load_end:
   migrate_end();

   if (r) {
       int rc = xenopsd_send_error_result(r);

       if (rc)
           emu_err("sending error to xenopsd failed: %d, %s",
                   -rc, strerror(-rc));
   }

   return r;
}

/*
 * Tell all emus to abort.
 * @return 0 on success. -errno on failure.
 */
static int migrate_abort(void)
{
    int i;
    int r;
    emu_info("attempting to abort");

    for (i=0; i < num_emus; i++) {
        if (emus[i].enabled) {
            switch (emus[i].proto) {
            case emp:
                r = em_socke_send_cmd(emus[i].sock, cmd_migrate_abort);
                if (r)
                    return r;
            break;
            case qmp:
            break;
            }
        }
    }
    return 0;
}

static int operation_save(void)
{
   int r;
   int end_r;

   int can_abort = true;

   configure_emus();

   r = startup_emus();
   if (r)
       goto migrate_end;

   r = connect_emus();
   if (r)
       goto migrate_end;

   r = init_emus();
   if (r)
       goto migrate_end;


   /* Live migrate * * * * * * * */
   if (gLive) {

       r = request_track_emus();
       if (r)
           goto migrate_end;

       r = migrate_live_emus();
       if (r)
           goto migrate_end;

       r = wait_on_condition(check_live_not_started);
       if (r)
           goto migrate_end;
   }

   can_abort = false;

   emu_info("ask xenopsd to suspend");
   r = xenopsd_send_suspend();
   if (r)
        goto migrate_end;

   emu_info("should be suspended, send paused to emus");

   r = pause_emus();
   if (r)
       goto migrate_end;

   wait_on_condition(check_live_not_finished);

   emu_info("send non-live data");

   r = save_nonlive_one_by_one();

   emu_info("sending result");
   xenopsd_send_final_result();

migrate_end:
   end_r = 0;
   if (r && can_abort)
       end_r = migrate_abort();

   if (end_r == 0) {
       emu_info("ending");
       end_r = migrate_end();
   }

   if (r || end_r) {
       emu_err("Failed!\n");

       if (end_r && !r)
           r = end_r;

       end_r = xenopsd_send_error_result(r);
       if (end_r)
           emu_err("sending error to xenopsd failed: %d, %s",
                   -end_r, strerror(-end_r));

       return 1;
   }

   return 0;
}



int main(int argc, char *argv[])
{
   int rc;
   char *ident;
   struct sigaction sa;

   parse_args(argc, argv);

   if (gMode == op_end)
      return 0;

   if (gMode == op_invalid)
      return 1;

    rc = asprintf(&ident, "%s-%d", basename(argv[0]), gDomid);
    if (rc > 0)
        openlog(ident, LOG_PID, LOG_DAEMON);

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL)) {
        emu_err("Error ignoring SIGPIPE %d, %s", errno, strerror(errno));
        return 1;
    }

   emu_info("starting ... ");

   emu_info("xenopsd control fds (%d, %d)", xenopsd_in, xenopsd_out);

   switch (gMode) {
   case op_pvsave:
       rc = argument_add(&emus[0].extra, "pv", "true");
       if (rc) {
           emu_err("Error adding pv argument: %d, %s", -rc, strerror(-rc));
           return 1;
       }
       /* fall though */
   case op_save:
      setvbuf(stdout, NULL, _IONBF, 0);
      return operation_save();
   case op_pvrestore:
      rc = argument_add(&emus[0].extra, "pv", "true");
      if (rc) {
          emu_err("Error adding pv argument: %d, %s", -rc, strerror(-rc));
          return 1;
      }
      /* fall though */
   case op_restore:
      return operation_load();
   default:
      emu_err("Invalid mode");
      return 1;
   }

}
