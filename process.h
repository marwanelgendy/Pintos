#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct child_processes* get_child_from_parent (struct thread* parent, tid_t child_tid);

void connect_parent_child (struct thread* parent, struct thread* child);

#endif /* userprog/process.h */
