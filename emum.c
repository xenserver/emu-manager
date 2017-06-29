#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <termios.h>
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

emu_arg_mode
};

int gDomid=0;
int gFd_in=0;
int gFd_out=0;
int gLive=0;

enum protocol {
emp,
qmp
};

struct emu {
    char *name;
    char *startup;
    char *waitfor;
    enum protocol proto;
    int enabled;
    int live_check;
    emu_socket_t* sock;
    int stream;
};
#define num_emus 2
struct emu emus[num_emus] = {
    {"xenguest", "/usr/libexec/xen/bin/xenguest -debug -domid %d -controloutfd 2 -controlinfd 0 -mode listen -live", "Ready", emp, true  , true ,NULL,0},
    {"vgpu"    , NULL                                                                                              , NULL   , emp, false , false,NULL,0}
};

#define emu_info(args...) syslog(LOG_DAEMON|LOG_INFO, args)
#define emu_err(args...) syslog(LOG_DAEMON|LOG_ERR, args)


/* xenops interface */

int do_suspend_guest_callback(void)
{

    static const char suspend_message[] = "suspend:\n";
    char buf[8];
    char *sbuf;
    ssize_t len, i;
    int got_something=0;


    emu_info("Talk to xenopsd on fds %d %d", gFd_in, gFd_out);

    /* Check nothing waiting */

    struct pollfd pfd = { .fd = gFd_in, .events = POLLIN };
    while( poll(&pfd, 1, 0)==1) {
        len = read(gFd_in, buf, sizeof(buf)-1);
         buf[len]=0;
        emu_info("Read %zu bytes '%s'", len, buf);
    /* data available */
    }


    write(gFd_out, suspend_message, sizeof(suspend_message)-1);

    /* Read one line from control fd. */
    for (;;) {

        len = read(gFd_in, buf, sizeof(buf));
        if (len < 0 && errno == EINTR)
            continue;
        if (len < 0) {
            emu_err("xenguest: read from control FD failed: %s\n", strerror(errno));
            return -1;
        }
        if (len == 0) {
            emu_err("xenguest: unexpected EOF on control FD\n");
            return -1;
        }
        sbuf=buf;
        for ( i = 0; i < len; ++i )
            if (sbuf[i] == '\n'){
                   sbuf[i]=0;
                   emu_info("Got message '%s'", sbuf);
                   sbuf=&sbuf[i+1];
                   len-=(i+1);
                   i=-1;
                   got_something=1;
            }
       if (len>0) {
           sbuf[len]=0;
           emu_info("Still here, had %zu bytes remaning with '%s'", len, sbuf);
       }
       if (got_something)
            return 0;
    }

}


int sent_result(void) {
    static const char finished_message[] = "result:0 0\n";
    return (write(gFd_out,finished_message, sizeof(finished_message)-1)>0)?0:-1;
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


int find_emu(char* emu_str, char** remaining)
{
   int emu;
   int len;
   *remaining=NULL;

   for (len=0; (emu_str[len] > ' ' && emu_str[len] != ':'); len++);

   if (emu_str[len] == ':')
     *remaining = &emu_str[len+1];

   for (emu=0; emu < num_emus; emu++) {
       if (strncmp(emus[emu].name, emu_str, len)==0)
           return emu;
   }
   return -1;
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

        { NULL },
    };


    int c;

    for(;;) {
        int arg_index = 0;
        int emu=-1;
        char* param=NULL;

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
             emu = find_emu(optarg, &param);
             if (emu >=0 && param) {
                 emus[emu].stream = parse_int(param);
                 emus[emu].enabled = true;
             } else {
                 emu_err("Bad DM args, Got '%s', refering to %d, param '%s'", optarg, emu, param);
             }
        break;
        case emu_arg_mode:
        break;
        }
    }
}

EMP_COMMANDS(commands);

void trim(char str[], int len)
{
    int i;
    str[len]='\0';
    for (i=0; str[i]>0x1f; i++);
    str[i]='\0';
}

/* Send messge to all emus */

int broudcast(int msg)
{
    int i;
    int r;
    for (i=0; i< num_emus; i++) {
        if (!emus[i].enabled)
             continue;

        r = em_socke_send_cmd(emus[i].sock,msg , 0);
        if (r < 0) {
            emu_err("Failed to send msg %d for %s\n",msg ,emus[i].name);
            return -1;
        }
    }
    return 0;
}


/* This prevents stdout being buffered */
int setenv_nobuffs()
{
    clearenv();
    if ((putenv("LD_PRELOAD=/usr/libexec/coreutils/libstdbuf.so")!=0) ||
        (putenv ("_STDBUF_O=0") != 0)) {
        emu_err("Failed to putenv\n");
        return -1;
    }
    return 0;
}


int start_emu(char command[], char ready[]) {


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
   for (;*next_word==' '; next_word++);

   if (*next_word) {
      for (; next_word[count]!=' ' && next_word[count]!='\0'; count++);
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
   if (pipe2( filedes, 0) == -1) {
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



int startup_emus() {
int i;

    for (i=0; i< num_emus; i++) {
        if (emus[i].startup) {
           emu_info("Starting %s\n", emus[i].name);
           if (start_emu(emus[i].startup, emus[i].waitfor))
              return -1;
        }
    }
    return 0;
}

/* where events are parsed */
int emu_callback(json_object *jobj, emu_socket_t* sock) 
{
   json_object *event=NULL;
   json_object *data=NULL;

   json_object_object_foreach(jobj, key, val) {
      if (strcmp(key, "data") == 0)
         data=val;
      if (strcmp(key, "event") == 0)
         event=val;
   }

   if (event && data) {
        int r;
        const char* ev_str=NULL;
        r = json_object_get_type(event);
        if (r == json_type_string) {
            ev_str= json_object_get_string(event);
        }

        if (strcmp(ev_str,"MIGRATION")==0) {
           int rem = -1;
           int iter = -1;
           int sent = -1;

           json_object_object_foreach(data, key, val) {
             if (strcmp(key, "status")==0) {
               emu_info("emu status Finished!");
               sock->status = all_done;

             } else if (json_object_get_type(val) == json_type_int) {
               int v = json_object_get_int(val);

               if (strcmp(key, "remaining")==0)
                   rem = v;
               else if (strcmp(key, "iteration")==0) {
                    iter = v;
               }
               else if (strcmp(key, "sent")==0) { 
                    sent = v;
               } else {
                   emu_info("sent unexpected %s of value %d", key, v);
               };
             } else
                   emu_info("Unexpected magrtion data %s", key);
             } // for
             if (rem >=0 || iter >= 0) {
                 int ready = (sock->status == live_done);
                 emu_info("rem %d, iter %d, send %d %s", rem, iter, sent, (ready)?" Waiting":"");
                 if ((iter>0) && (rem < 50 || iter >= 4) && !ready) {
                     emu_info("criteria met - signal ready");
                    sock->status= live_done;
                 }
             }

        } else
        {
         emu_info("Unkown event type '%s'. Ignoring.", ev_str);
        }
   } else {
      emu_err("Called on sametihng not an event");
   }

   return 0;
}

int init_emus() {

    int i;
    int r;
    char fname[128];

    for (i=0; i< num_emus; i++) {
        int r;
        if (!emus[i].enabled)
             continue;
        snprintf(fname, 128, CONTROL_PATH, emus[i].name, gDomid); 
        r = em_socket_alloc(&emus[i].sock, &emu_callback, &emus[i]);
        if (r<0) {
            emu_err("Alloc socket for %s\n", emus[i].name);
            return -1;
        }

        r = em_socket_open(emus[i].sock, fname);
        if (r < 0) { 
            emu_err("Failed to connect to %s\n", emus[i].name);
            return -1;
        }

    }

   for (i=0; i< num_emus; i++) {
        if (!emus[i].enabled)
             continue;

        r = em_socke_send_cmd(emus[i].sock,cmd_migrate_init , emus[i].stream);
        if (r < 0) {
            emu_err("Failed to init %s\n", emus[i].name);
            return -1;
        }
    }
    r = broudcast(cmd_migrate_progress);
    return r;
}



int migrate_emus() {
  int i;
  int r;

  for (i=0; i< num_emus; i++) {
        if (!emus[i].enabled)
             continue;

        r = em_socke_send_cmd(emus[i].sock,cmd_migrate_live , 0);
        if (r < 0) {
            emu_err("Failed to start live migrate for %s\n", emus[i].name);
            return -1;
        }
    }

    return 0;
}

int migrate_paused() {
    int i;
    int r;
    for (i=0; i< num_emus; i++) {
        if (!emus[i].enabled)
             continue;

        r = em_socke_send_cmd(emus[i].sock,cmd_migrate_paused , 0);
        if (r < 0) {
            emu_err("Failed to indicate paused for %s\n", emus[i].name);
            return -1;
        }
    }
    return 0;
}

int migrate_end() {
   int fd;
   int i;

   for (i=0; i< num_emus; i++) {
      if (emus[i].sock) {

         fd = emus[i].sock->fd;
         if (fd) {
            if ( fd && emus[i].startup)
              em_socke_send_cmd(emus[i].sock,cmd_quit, 0);
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

int wait_for_event()
{

    int             i;
    int             rc;
    fd_set          rfds;
    fd_set          wfds;
    fd_set          xfds;
    int             max_fd=0;
    struct timeval  tv;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    tv.tv_sec = 10;
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

      for (i=0; i< num_emus; i++) {
           if (emus[i].enabled && FD_ISSET(emus[i].sock->fd, &rfds)) {
               int r;
               r = em_socket_read(emus[i].sock);
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
   return rc;
}

int wait_for_finished()
{
    int i;
    int r;
    int finished=0;
    while (!finished) {
        finished=1;
        for (i=0; i< num_emus; i++) {
            if ((emus[i].enabled) && (emus[i].sock->status != all_done)) {
               emu_info("Waiting for %s to finish", emus[i].name);
               finished=0;
               break;
            }
         }

         if (!finished) {
             r = wait_for_event();

             if (r < 0 && errno != EINTR) {
                  emu_err("Got error while waiting for events");
                  return -1;
             }
         }
    }
    return 0;
}


int wait_for_ready()
{
    int i;
    int r;
    int waiting=1;
    while (waiting) {
        for (i=0; i< num_emus; i++) {
            if ((emus[i].enabled) && (emus[i].sock->status > not_done)) {
               waiting=0;
               continue;
            }
         }

          if (waiting) {
              r = wait_for_event();

              if (r < 0 && errno != EINTR) {
                  emu_err("Got error while waiting for events");
                  return -1;
              }
          }
    }
    return 0; 
}


int migrate_finish() {
   wait_for_finished();

    return 0;
}


int main(int argc, char *argv[])
{
   int r;
   int end_r;

   for (r=1; r < argc; r++) {
       if ((strcmp(argv[r], "-mode")==0) && (strcmp(argv[r+1], "hvm_save")==0))
           goto itsok;
   }


   execvp("/root/xenguest", argv);

itsok:

   parse_args(argc, argv);

   setvbuf(stdout, NULL, _IONBF, 0);

   r = startup_emus();
   if (r)
       goto migrate_end;

   r = init_emus();
   if (r)
       goto migrate_end;

   r = migrate_emus();
   if (r)
       goto migrate_end;

   wait_for_ready();

   broudcast(cmd_migrate_pause);

   emu_info("ask xenopsd to suspend");
   r = do_suspend_guest_callback();
   if (r)
        goto migrate_end;

   emu_info("should be suspended, send paused to emus");

   r = migrate_paused();
   if (r)
       goto migrate_end;

   r = migrate_finish();

   sent_result();

migrate_end:

   end_r = migrate_end();

   if (r || end_r)
      emu_err("Failed!\n");

   return 1;
}
