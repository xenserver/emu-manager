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
#include <syslog.h>

#define CONTROL_PATH "/var/xen/%s/%d/control"

#include <poll.h>
#include <stdbool.h>

enum emu_mon_args {
emu_arg_controlinfd,
emu_arg_controloutfd,
emu_arg_debuglog,
emu_arg_fd,
emu_arg_domid,
emu_arg_live,
emu_arg_dm,

emu_arg_mode,

/* resume args */
emu_arg_xg_store_port,
emu_arg_xg_console_port,
emu_arg_fork,

emu_arg_supports
};

enum operation_mode {
   op_invalid = -1,
   op_save    = 0,
   op_pvsave,
   op_restore,
   op_pvrestore,
   op_end
};

static const char* mode_names[] = {"hvm_save","save", "hvm_restore", "restore", NULL};

static const char* supports_table[] = {"migration-v2", NULL};


int gDomid  = 0;
int gFd_in  = 0;
int gFd_out = 0;
int gLive   = 0;
int gLastUpdateP = -1;
enum operation_mode gMode=op_invalid;

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
    char *startup;
    char *waitfor;
    enum protocol proto;
    int enabled;

    int live_check;

    int exp_total;

    emu_socket_t* sock;
    int stream;

    enum state status;
    char* result;
    int error;
    struct args_list* extra;
    struct data_stats* data_stats;
};



#define num_emus 3

#define XENGUEST_ARGS  "/usr/libexec/xen/bin/xenguest -debug -domid %d -controloutfd 2 -controlinfd 0 -mode listen"

struct emu emus[num_emus] = {
//   name      , startup               , proto, enabled,                   livech , gues_tot, sock, stream, status, result, err, extra, stats
    {"xenguest", XENGUEST_ARGS, "Ready", emp, (FULL_LIVE | STAGE_ENABLED) , true  , 1000000, NULL,     0  , not_done, NULL, 0   , NULL, NULL},
    {"vgpu"    , NULL         , NULL   , emp, FULL_LIVE                   , false , 100000,  NULL,     0  , not_done, NULL, 0   , NULL, NULL},
    {"qemu"    , NULL         , NULL   , qmp, FULL_NONLIVE                , false , 10,      NULL,     0  , not_done, NULL, 0   , NULL, NULL}

};

#define emu_info(args...) syslog(LOG_DAEMON|LOG_INFO, args)
#define emu_err(args...) syslog(LOG_DAEMON|LOG_ERR, args)


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

static int do_receive_emu(int emu_i);

static void free_extra_arg(struct args_list *xa)
{
      free(xa->key);
      free(xa->value);
      free(xa);
}

static int add_extra_arg(struct emu *emu, const char* key, char* value)
{
   struct args_list *xa;
   struct args_list **lp;

   xa = malloc(sizeof(struct args_list));

   if (xa == NULL)
        return -1;

   xa->key = strdup(key);
   xa->value = strdup(value);
   xa->next = NULL;

   if (xa->key == NULL || xa->value == NULL) {
       free_extra_arg(xa);
       emu_err("Failed to alloc extra arg");
       return -1;
   }

   emu_info("LLS");
   lp = &emu->extra;

   while (*lp) {
       emu_info("LL");
       lp = &((*lp)->next);
   }
   *lp = xa;
   return 0;
}


static int find_emu_by_name(char name[])
{
   int emu;
   for (emu=0; emu < num_emus; emu++) {
       if (strcmp(emus[emu].name, name)==0)
           return emu;
   }
   return -1;
}

static int trim(char str[], int len)
{
    int i;
    str[len]='\0';
    for (i=0; str[i]>0x1f; i++);
    str[i]='\0';
    return i;
}

static int split(char strA[], char** strB, char delim)
{
   int pos;

   for (pos=0; (strA[pos] > '\0' && strA[pos] != delim); pos++);

   if (strA[pos] == delim)
       *strB = &strA[pos+1];
   else
       *strB = NULL;

   return pos;
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


/* xenops interface */


static int read_tlimit(int fd, char* buf, size_t len, int time)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r;

    r = poll(&pfd, 1 , time * 1000);
    if (r == 0) {
      r = -1;
      errno = ETIME;
    }

    if(r > 0)
       r = read( fd, buf, len );
    return r;
}

#define XENOPSD_MSG_SIZE 128




const char* in_cmds[] = {"restore", NULL};

#define BAD_ARGS             1
#define GOT_SOMETHING        2
#define UNDERSTOOD_SOMETHING 3


static int process_xod_line(char* buf)
{
    char* cmd_s;
    char* emu_name;
    int r=0;
    int cmd;

    emu_info("Processing \"%s\"", buf);

    r = split(buf, &emu_name, ':');
    if (r<0) {
        emu_err("Read bad string '%s' from xenopsd", buf);
        return BAD_ARGS;
    }

    if (emu_name) {
       cmd_s= strndupa(buf, r);
    } else {
       cmd_s = buf;
    }

    cmd =  str_lookup(in_cmds, cmd_s);
    if (cmd < 0) {
        emu_info("Something not recognised \"%s\"", cmd_s);
        return GOT_SOMETHING;
    }
    /* only one command - must be restore */

    if (!emu_name) {
       emu_err("No param provided");
       return BAD_ARGS;
    }

    r = find_emu_by_name(emu_name);
    if ( r < 0) {
       emu_err("Did do not know '%s'", emu_name);
       return BAD_ARGS;
    }

    emu_info("Got recieve for %d: %s", r , emu_name);
    do_receive_emu(r);
    return UNDERSTOOD_SOMETHING;

}

char* xenopd_message_carry = NULL;

static int read_xenopd_message(char ** result)
{
    char *buf=NULL;
    char *line;
    char *next_line;
    int max = XENOPSD_MSG_SIZE-1;
    int rec=0;
    int r=-1;
    int offset=0;
    int end;
    int resume_proc = false;

   /* if already read, see if we can just resume processing */
   line = xenopd_message_carry;
   if (line) {
       for (end=0; (line[end]!='\n' && line[end]!='\0'); end++);
       if (line[end]=='\n') {
           buf = line;
           resume_proc = true;
           xenopd_message_carry = NULL;
       }
   }
   if (!buf)
         buf = alloca(XENOPSD_MSG_SIZE);

   /* carry, but not compleat line */
   if (xenopd_message_carry) {
      offset = strlen(xenopd_message_carry);
      strcpy(buf, xenopd_message_carry);
      free(xenopd_message_carry);
      xenopd_message_carry=NULL;
      max -= offset;
   }

   /* if need be, read some more */
   if (!resume_proc) {
       rec = read_tlimit(gFd_in, (buf + offset), max, XENOPSD_TIMOUT);

       if ( rec <= 0 ) {
           if (rec<0)
                 emu_info("Read returned error: %s", strerror(errno));
           else
                 emu_info("Read return EOF");
          r = rec;
          goto stop;
       }
       rec+=offset;
       buf[rec] = '\0';
       emu_info("read_xenopd_message: Read return \"%s\"", buf);

   }

   /* Go thought line by line */
    next_line = buf;
    do {
       line = next_line;
       /* find line */
       for (end=0; (line[end]!='\n' && line[end]!='\0'); end++);

       emu_info("read_xenopd_message: line =\"%s\", end = %d", line, end);

       if (line[end]!='\n') {
          /* Not a compleat line */
          xenopd_message_carry = strdup(line);
          /* r == -1 or UNDERSTOOD_SOMETHING */
          if (r==-1) {
               emu_err("line to long to parse");
               errno=EMSGSIZE;
          }
          emu_info("not full line");
          goto stop;
       }

      line[end]='\0';
      r = process_xod_line(line);

      next_line = &line[end+1];
    } while ((r == UNDERSTOOD_SOMETHING) && next_line[0]!='\0');

   if ( r == GOT_SOMETHING) {
         if (result)
             *result = strndup(line,end);
         else
            emu_info("got unexpected line \"%s\"", line);
   }

   if (next_line[0] != '\0') {
       xenopd_message_carry = strdup(next_line);
       emu_info("carry");
   }

stop:

   if (resume_proc)
      free(buf);
   return r;
}

static int send_xenopd_message(char* message)
{
    int rc;

    emu_info("Send '%s' to xenopsd on fds %d %d",message,  gFd_in, gFd_out);

    rc = write_all(gFd_out, message, strlen(message));
    if (rc)
        emu_err("Failed to write to xenopsd %d, %s", -rc, strerror(-rc));

    return rc;
}

static int send_xenopsd_progress(int prog)
{
    char* buf;
    int r = asprintf(&buf, "info:\\b\\b\\b\\b%d\n", prog);
    if (r <= 0)
        return -1;

    send_xenopd_message(buf);
    free(buf);
    return 0;
}

static int update_progress(void)
{

   int progress = calculate_done();

   if (gLastUpdateP != progress) {
       send_xenopsd_progress(progress);
       gLastUpdateP = progress;
   }
   return progress;
}

static int send_xenopd_message_reply(char* message)
{
   char* buf;
   int r = send_xenopd_message(message);
   if (r)
      return r;

   for (;;) {
      r = read_xenopd_message(&buf);
      if (r < 0 && errno == EINTR)
            continue;
      if (r == 0) {
            emu_err("Unexpected EOF on control FD\n");
            return -1;
        }
      if (r == BAD_ARGS) {
          emu_err("Bad responce");
          return -1;
      }
      emu_info("Got something - '%s', that'll do", buf);
      free(buf);
      return 0;
  }
}

static int do_suspend_guest_callback(void)
{
    return send_xenopd_message_reply("suspend:\n");
}

static int xod_save_emu(int emu)
{
   char buf[XENOPSD_MSG_SIZE];

   assert(emu < num_emus);

   snprintf(buf, XENOPSD_MSG_SIZE, "prepare:%s\n", emus[emu].name);
   return send_xenopd_message_reply(buf);
}

static int send_result(struct emu* emu) {
     char* buffer;
     int r;

     if (emu->result)
        r = asprintf(&buffer, "result:%s %s\n", emu->name, emu->result);
     else
        r = asprintf(&buffer, "result:%s\n", emu->name);

    if (r < 0) {
       emu_err("asprintf failed");
       return r;
    }

    r = send_xenopd_message(buffer);
    free(buffer);
    return r;
}

static int send_final_result(void)
{
    return send_xenopd_message("result:0 0\n");
}

/*
 * Sends @err as an error result to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int send_error_result(int err)
{
    char msg[XENOPSD_MSG_SIZE];
    int rc;

    rc = snprintf(msg, XENOPSD_MSG_SIZE, "error:error code %d\n", err);
    if (rc < 0)
        return -errno;

    return send_xenopd_message(msg);
}

static int parse_int(const char *str)
{
    char *st_end;
    int result;

    result = strtol(str, &st_end, 10);

    if (*st_end != '\0') {
        emu_err("Cannot parse '%s' as a valid integer\n", str);
        exit(1);
    }

    return result;
}


static int find_emu(char* emu_str, char** remaining)
{
   int len;
   *remaining=NULL;

   for (len=0; (emu_str[len] > ' ' && emu_str[len] != ':'); len++);

   if (emu_str[len] == ':') {
     *remaining = &emu_str[len+1];
     emu_str[len]='\0';
   }

   return find_emu_by_name(emu_str);
}

static void get_dm_param(char* arg)
{
   int emu=-1;
   char *param=NULL;
   char *emu_name;

   emu_name = strdup(arg);

   emu = find_emu(emu_name, &param);


   if (emu < 0) {
       if (param)
           emu_err("Bad DM args, Got '%s'", emu_name);
       else
           emu_err("Bad DM args, got '%s' with args '%s'", emu_name, param);

       free(emu_name);
       exit(1);
   }

   emus[emu].enabled |= STAGE_ENABLED;

   if (param) {
       if (emus[emu].proto == emp) {
           emus[emu].stream = parse_int(param);
       } else {
           emu_err("Bad DM args, Got '%s', refering to %d, param '%s'", optarg, emu, param);
           emus[emu].enabled = false;
       }
    }
    free(emu_name);
}


static void parse_args(int argc, char *const argv[])
{
    static const struct option args[] = {
        { "controlinfd" , required_argument, NULL, emu_arg_controlinfd, },
        { "controloutfd", required_argument, NULL, emu_arg_controloutfd, },
        { "debuglog"    , required_argument, NULL, emu_arg_debuglog, },
        { "fd"          , required_argument, NULL, emu_arg_fd, },
        { "domid"       , required_argument, NULL, emu_arg_domid, },
        { "live"        , no_argument      , NULL, emu_arg_live, },
        { "dm"          , required_argument, NULL, emu_arg_dm, },

        { "mode"        , required_argument, NULL, emu_arg_mode, },


        {"store_port", required_argument,    NULL, emu_arg_xg_store_port, },
        {"console_port", required_argument,  NULL, emu_arg_xg_console_port, },
        {"fork", required_argument,          NULL, emu_arg_fork,          },

        {"supports"     , required_argument, NULL, emu_arg_supports, },
        { NULL },
    };


    int c;

    for(;;) {
        int arg_index = 0;

        c = getopt_long_only(argc, argv, "", args, &arg_index);

        switch (c) {
        case -1:
            return;

        case emu_arg_controlinfd:
             gFd_in=parse_int(optarg);
        break;
        case emu_arg_controloutfd:
             gFd_out=parse_int(optarg);
        break;
        case emu_arg_debuglog:
        break;
        case emu_arg_fd:
         emus[0].stream = parse_int(optarg);
        break;
        case emu_arg_domid:
             gDomid=parse_int(optarg);
        break;
        case emu_arg_live:
             gLive = 1;
        break;
        case emu_arg_dm:
             get_dm_param(optarg);
        break;
        case emu_arg_mode:
           gMode = str_lookup(mode_names, optarg);
           if (gMode<0)
               emu_err("Don't know mode  '%s'",optarg);
        break;

        case emu_arg_xg_store_port:
        case emu_arg_xg_console_port:
             emu_info("adding xenguest special option %s = %s", args[arg_index].name, optarg);
             add_extra_arg(&emus[0], args[arg_index].name, optarg);
        break;
        case emu_arg_fork: /* ignore */
        break;
        case emu_arg_supports:
             gMode = op_end;
             if (str_lookup(supports_table, optarg) >=0)
                 printf("true\n");
             else
                 printf("false\n");
        break;
        }
    }
}

EMP_COMMANDS(commands);

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

static int start_emu(char command[], char ready[])
{
  int filedes[2];


   char *buf;
   const char    *my_argv[64];
   int args=0;

   char *next_word= command;
   int count=0;
   pid_t   my_pid;
   char buffer[1024];

   do {
       count=0;
       for (;*next_word==' '; next_word++)
           ;

       if (*next_word) {
           for (; next_word[count]!=' ' && next_word[count]!='\0'; count++)
               ;

           if (count) {
               if ((next_word[0] == '%') && (next_word[1] == 'd')) {
                   buf = alloca(11);
                   snprintf(buf, 11, "%d", gDomid);
               } else {
                   buf = alloca(count+1);
                   strncpy(buf, next_word, count);
                   buf[count]='\0';
               }
               my_argv[args]=buf;
               args++;

               next_word +=count;
           }
       }
   } while (count);
   my_argv[args]=NULL;

// -------------------
   if (pipe(filedes) == -1) {
     perror("pipe");
    return -1;
   }

   emu_info(" fd = %d\n", filedes[1]);

   my_pid = fork();

   if (my_pid == -1) {
      perror("forked");
      return -1;
   } else if (my_pid == 0) {
      setvbuf(stdout, NULL, _IONBF, 0);

      while ((dup2(filedes[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}

      close(filedes[1]);
      close(filedes[0]);

      setenv_nobuffs();

      execvp(my_argv[0], (char **)my_argv);
      perror("child process execve failed :");
      exit(1);
   }

   emu_info("Parent waiting\n");
   // --------------------

   close(filedes[1]);

   while (1) {

      ssize_t count = read(filedes[0], buffer, sizeof(buffer));
      emu_info("--\n");
      if (count == -1) {
         if (errno == EINTR) {
            continue;
         } else {
            perror("read");
           return -1;
         }
      } else if (count == 0) {
         emu_info("EOF");
         return -1;
      } else {
          trim(buffer, count);
          if (strcmp(buffer, ready)==0) { 
              emu_info("emu ready");
              return 0;
          }
          emu_info("Ignoring \"%s\"\n", buffer);
      }
   }
}

/*
 * Start all emus that need to be started.
 * @return 0 on success. -errno on failure.
 */
static int startup_emus(void)
{
    int i;
    int rc;

    for (i=0; i< num_emus; i++) {
        if (emus[i].startup) {
           emu_info("Starting %s\n", emus[i].name);
           rc = start_emu(emus[i].startup, emus[i].waitfor);
           if (rc) {
               emu_err("Error starting %s: %d, %s",
                       emus[i].name, -rc, strerror(-rc));
              return rc;
           }
        }
    }
    return 0;
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
 * Open a connection to @emu.
 * @return 0 on success. -errno on failure.
 */
static int connect_emu(struct emu* emu)
{

    int r;
    char fname[128];

    snprintf(fname, 128, CONTROL_PATH, emu->name, gDomid); 
    r = em_socket_alloc(&emu->sock, &emu_callback, emu);
    if (r)
        return r;

    return em_socket_open(emu->sock, fname);
}

/*
 * Connect to all emus.
 * @return 0 on success. -errno on failure.
 */
static int connect_emus(void)
{
   int i;
   int r;
   struct emu* emu;

   /* establish connection */

   for (i=0; i< num_emus; i++) {
      emu = &emus[i];
      if (!emu->enabled)
          continue;

      switch (emu->proto) {
      case emp:
      case qmp:
              if ((r = connect_emu(emu))) {
                 emu_err("Failed to open socket for %s: %d, %s",
                         emu->name, -r, strerror(-r));
                 return r;
              }
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
   int r;
   struct emu* emu;

   /* init each emu */

   for (i=0; i< num_emus; i++) {
        emu = &emus[i];
        if (!(emu->enabled && STAGE_INIT))
             continue;

        switch (emu->proto) {
        case emp:
             emu_info("Init %s with fd %d", emu->name, emu->stream);
             r = em_socke_send_cmd_fd(emu->sock, cmd_migrate_init , emu->stream);
             if (r)
                 return r;

             if (emu->extra) {
                  emu_info("sending extra args");
                  r = em_socke_send_cmd_args(emu->sock, cmd_set_args, emu->extra);
                  if (r)
                      return r;
             }

        break;
        case qmp:

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
   int r;
   struct emu* emu;

   /* init each emu */

   for (i=0; i< num_emus; i++) {
        emu = &emus[i];
        if (!(emu->enabled && STAGE_LIVE  ))
             continue;


        switch (emu->proto) {
        case emp:

            r = em_socke_send_cmd(emu->sock,cmd_track_dirty);
            if (r)
                return r;

            r = em_socke_send_cmd(emu->sock,cmd_migrate_progress);
            if (r)
                return r;

        break;
        case qmp:

        break;
        }
   }
   return 0;
}

static int do_receive_emu(int emu_i)
{
    int r;
    struct emu* emu = &emus[emu_i];

    if (emus[emu_i].status != not_done) {
        emu_err("Request to receive emu '%s' already in progress", emu->name);
        return -1;
    }

    emu_info("restore %d: %s", emu_i, emu->name);
    r = em_socke_send_cmd(emu->sock, cmd_restore);
    if (r < 0) {
        emu_err("Failed to start restore for %s\n", emu->name);
        return -1;
    }
    emus[emu_i].status = started;
    return 0;
}

/*
 * Start migration for each live emu.
 * @return 0 on success. -errno on failure.
 */
static int migrate_emus(void)
{
  int i;
  int r;

  for (i=0; i< num_emus; i++) {
        if (!(emus[i].enabled & STAGE_LIVE))
             continue;


        r = xod_save_emu(i);
        if (r < 0) {
             emu_err("Failed to prepare stream for %s: %d, %s\n",
                     emus[i].name, -r, strerror(-r));
             return r;

        }

        emu_info("Migrate live %d: %s", i, emus[i].name);
        r = em_socke_send_cmd(emus[i].sock,cmd_migrate_live);
        if (r)
            return r;
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
    int r;
    for (i=0; i< num_emus; i++) {
        if (!(emus[i].enabled & STAGE_PAUSED))
             continue;

        r = em_socke_send_cmd(emus[i].sock,cmd_migrate_paused);
        if (r)
            return r;
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
            close(fd);
         }
         free(emus[i].sock);
      }
      fd = emus[i].stream;
      if (fd)
          close(fd);
   }
   return 0;
}

static int wait_for_event(void)
{

    int             i;
    int             rc;
    fd_set          rfds;
    fd_set          wfds;
    fd_set          xfds;
    int             max_fd = gFd_in;
    struct timeval  tv;

    int was_more = false;;

/* Check for existing data */


    for (i=0; i< num_emus; i++) {
         if (!emus[i].enabled)
            continue;

         if (emus[i].sock->more) {

            int r;

            was_more=true;

            r = em_socket_read(emus[i].sock, false);
            if (r < 0) {
                 emu_err("Failed to read from %s\n",emus[i].name);
                 return -1;
            }
            if (r > 0) {
                emu_err("Unexpected return from %s\n",emus[i].name);
                return -1;
            }
         }
    }
    if (was_more)
       return 1;



    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    FD_SET(gFd_in, &rfds);

    tv.tv_sec = 30;
    tv.tv_usec = 0;

    for (i=0; i< num_emus; i++) {
        int fd;
        if (!emus[i].enabled)
            continue;
        fd =  emus[i].sock->fd;
        FD_SET(fd, &rfds);
        if (fd> max_fd)
            max_fd = fd;
    }

   rc = select(max_fd + 1, &rfds, &wfds, &xfds, &tv);

   if (rc > 0) {

      if (FD_ISSET(gFd_in, &rfds)) {
          rc = read_xenopd_message(NULL);
          emu_info("control message rc = %d", rc);
          if (rc <= 0 )
             return rc;
      }

      for (i=0; i< num_emus; i++) {
           if (emus[i].enabled && FD_ISSET(emus[i].sock->fd, &rfds)) {
               int r;
               r = em_socket_read(emus[i].sock, true);
               if (r < 0) {
                   emu_err("Failed to read from %s\n",emus[i].name);
                   return -1;
               }
               if (r > 0) {
                   emu_err("Unexpected return from %s\n",emus[i].name);
                   return -1;
               }
           }
      }
   }
   if (rc==0) {
        errno = ETIME;
        return -1;
   }

   return rc;
}

static int wait_for_finished(void)
{
    int i;
    int r;
    int finished=0;
    while (!finished) {
        finished=1;
        for (i=0; i< num_emus; i++) {
            if ((emus[i].enabled & STAGE_LIVE) && (emus[i].status != all_done)) {
               emu_info("Waiting for %s to finish", emus[i].name);
               finished=0;
               break;
            }
         }

         if (!finished) {
             r = wait_for_event();

             if (r < 0 && errno != EINTR && errno != ETIME) {
                  emu_err("Got error %s while waiting for events", strerror(errno));
                  return -1;
             }
            if (r==0) {
                  emu_err("xenopsd hung up");
                  return -1;

            }
            update_progress();
         }
    }
    return 0;
}

static int wait_for_ready(void)
{
    int i;
    int r;
    int waiting=1;
    int enabled = 0;
    while (waiting) {
        enabled = 0;
        for (i=0; i< num_emus; i++) {
            if (emus[i].enabled & STAGE_LIVE) {
                enabled++;
                emu_info("%s waiting for %d: %s", (emus[i].status> not_done)?"not":"", i, emus[i].name);
                if (emus[i].status > not_done)
                    waiting=false;
            }
         }
         if (enabled == 0)
            waiting = false;

         if (waiting) {
              r = wait_for_event();

              if (r < 0 && errno != EINTR && errno!= ETIME) {
                  emu_err("Got error while waiting for events");
                  return -1;
              }
              if (r==0) {
                  emu_err("xenopsd hung up");
                  return -1;
              }
         }
         update_progress();
    }
    return 0;
}

static int save_nonlive_one_by_one(void)
{
    int i;
    int r;

    for (i=0; i< num_emus; i++) {
        if (!(emus[i].enabled & STAGE_STOPCOPY))
            continue;
        emu_info("Save non-live (%d) %s", i, emus[i].name);

        r = xod_save_emu(i);
        if (r < 0)
            return r;

        r = em_socke_send_cmd(emus[i].sock, cmd_migrate_nonlive);
        if (r < 0) {
            emu_err("Failed to send msg %d for %s\n",cmd_migrate_nonlive ,emus[i].name);
            return -1;
        }

        while (emus[i].status != all_done) {
            r = wait_for_event();

            if (r < 0 && errno != EINTR && errno != ETIME) {
                     emu_err("Got error while waiting for events");
                     return -1;
            }
            update_progress();
        }

        if (emus[i].stream)
             syncfs(emus[i].stream);
    }
    return 0;
}

static void config_emus(void)
{
   int i;

   // Convert live to non-live process

   for (i=0; i < num_emus; i++) {

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
   int emu;
   int i;

   config_emus();

   r = startup_emus();
   if (r)
       goto load_end;

   r = connect_emus();
   if (r)
       goto load_end;

   r = init_emus();
   if (r)
       goto load_end;


   emu_info("Waiting for xenopsd");
   /* Wait for everything to finish */
   for (emu=0; emu < num_emus; emu++)
       if (emus[emu].enabled)
           while (emus[emu].status != result_sent) {

               for (i=0; i < num_emus; i++) {
                  if (emus[i].enabled) {
                      emu_info("%c%s %s", (i==emu)?'*':' ', emus[i].name, (emus[i].status==started)?"Waiting": ((emus[i].status>started)?"Done":"Pending"));
                  }
               }
               /* watch xenopd, to see what's comming */
               r = wait_for_event();
               if (r < 0 && errno != EINTR && errno != ETIME) {
                   emu_err("Error waiting on events %s", strerror(errno) );
                   goto load_end;
               } else if (r == 0) {
                   emu_err("Recived EOF");
                   r = -1;
                   goto load_end;
               }

               for (i=0; i < num_emus; i++) {
                   if (emus[i].status == all_done) {
                       if (emus[i].error) {
                            r = -1;
                            emu_err("EMU failed.");
                            goto load_end;
                       }
                       send_result(&emus[i]);
                       emu_info("emu %s complete", emus[i].name);
                       emus[i].status = result_sent;
                   }
               }

           }
   r = 0;

load_end:
   migrate_end();

   if (r) {
       int rc = send_error_result(r);

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

   config_emus();

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

       r = migrate_emus();
       if (r)
           goto migrate_end;

       r = wait_for_ready();
       if (r)
           goto migrate_end;
   }

   can_abort = false;

   emu_info("ask xenopsd to suspend");
   r = do_suspend_guest_callback();
   if (r)
        goto migrate_end;

   emu_info("should be suspended, send paused to emus");

   r = pause_emus();
   if (r)
       goto migrate_end;

   wait_for_finished();

   emu_info("send non-live data");

   r = save_nonlive_one_by_one();

   emu_info("sending result");
   send_final_result();

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

       end_r = send_error_result(r);
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

   switch (gMode) {
   case op_pvsave:
       add_extra_arg(&emus[0], "pv", "true");
       /* fall though */
   case op_save:
      setvbuf(stdout, NULL, _IONBF, 0);
      return operation_save();
   case op_pvrestore:
      add_extra_arg(&emus[0], "pv", "true");
      /* fall though */
   case op_restore:
      return operation_load();
   default:
      emu_err("Invalid mode");
      return 1;
   }

}
