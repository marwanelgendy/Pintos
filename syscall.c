#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"

void halt (void);
void exit_wrapper (void);
tid_t exec (void);
int wait (void);
bool create (void);
bool remove (void);
int open (void);
int filesize (void);
int read (void);
int write (void);
void seek (void);
unsigned tell (void);
void close (void);

void validate_address (void *address);
void* get_void_pointer (void*** stack_pointer);
char* get_char_pointer (char*** stack_pointer);
int get_int (int **stack_pointer);
void* stack_pointer;
// struct list all_files;
struct lock file_system_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  lock_init (&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  stack_pointer = f->esp;
  validate_address (f->esp);
  int sys_call = get_int ((int**) &stack_pointer);
  switch (sys_call)
  {
    case SYS_HALT:
        halt ();
        break;
    case SYS_EXIT:
        exit_wrapper ();
        break;
    case SYS_EXEC:
        f->eax = exec ();
        break;
    case SYS_WAIT:
        f->eax = wait ();
        break;
    case SYS_CREATE:
        f->eax = create ();
        break;
    case SYS_REMOVE:
        f->eax = remove ();
        break;
    case SYS_OPEN:
        f->eax = open ();
        break;
    case SYS_FILESIZE:
        f->eax = filesize ();
        break;
    case SYS_READ:
        f->eax = read ();
        break;
    case SYS_WRITE:
        f->eax = write ();
        break;
    case SYS_SEEK:
        seek ();
        break;
    case SYS_TELL:
        f->eax = tell ();
        break;
    case SYS_CLOSE:
        close ();
        break;
    default:
      break;
  }
}


void
halt (void)
{

  shutdown_power_off();
}

void
exit (int status)
{
  struct thread* child = thread_current ();
  struct thread* parent = get_thread (child->parent_id);
  if (parent != NULL) // update child info of the parent
  {
    struct child_processes* child_processes_elem = get_child_from_parent (parent, child->tid);
    if (child_processes_elem != NULL)
    {
      lock_acquire (&parent->wait_child);
      child_processes_elem->exit_status = status;
      lock_release (&parent->wait_child);
    }
  }

  child->exit_status = status;
  thread_exit ();
}

void
exit_wrapper (void)
{
  int status = get_int ((int**) &stack_pointer);
  exit (status);
}

tid_t
exec (void)
{
  char *cmd_line = get_char_pointer ((char***) &stack_pointer);
  // return process_execute (cmd_line);
  int pid = process_execute (cmd_line);
  if (pid == -1) return -1;

  sema_down (&thread_current ()->parent_child_sync);
  struct child_processes* child = get_child_from_parent(thread_current(), pid);
  if (child != NULL && child->loaded == false) return -1;
  return pid;
}

int
wait (void)
{
  int pid = get_int ((int**) &stack_pointer);
  return process_wait (pid);
}

bool
create (void)
{
  char* file = get_char_pointer ((char***) &stack_pointer);
  unsigned initial_size = get_int ((int**) &stack_pointer);
  lock_acquire (&file_system_lock);
  bool create_status = filesys_create (file, initial_size);
  lock_release (&file_system_lock);
  return create_status;
}

bool
remove (void)
{
  char* file = get_void_pointer ((char***) &stack_pointer);
  lock_acquire (&file_system_lock);
  bool remove_status = filesys_remove (file);
  lock_release (&file_system_lock);
  return remove_status;
}

int
open (void)
{
  struct thread* cur = thread_current ();
  char* file_name = get_char_pointer ((char***) &stack_pointer);
  lock_acquire (&file_system_lock);
  struct file* file = filesys_open (file_name);
  int descriptor_return = -1;
  if (file != NULL)
  {
    struct open_file *file_des = malloc (sizeof (struct open_file));
    file_des->file = file;
    file_des->fd = cur->fd_last++;
    descriptor_return = file_des->fd;
    list_push_back (&cur->files, &file_des->thread_elem);
    // list_push_back (&all_files, &file_des->elem);
  }
  lock_release (&file_system_lock);
  return descriptor_return;
}

int
filesize (void)
{
  struct thread* cur = thread_current ();
  int fd = get_int ((int**) &stack_pointer);
  lock_acquire (&file_system_lock);
  struct open_file* file_des = get_open_file (cur, fd);
  int length = -1;
  if (file_des != NULL)
  {
    struct file* file = file_des->file;
    length = file_length (file);
  }
  lock_release (&file_system_lock);
  return length;
}

int
read (void)
{
  int fd = get_int ((int**) &stack_pointer);
  void* buffer = get_void_pointer ((void***) &stack_pointer);
  unsigned length = get_int ((int**) &stack_pointer);
  int ret_value = length;
  lock_acquire (&file_system_lock);

  if (fd == 0) // read from keyboard
  {
    for (int i = 0; i < length; i++)
    {
      uint8_t value = input_getc (); // uint8_t as defined in the library :(
      *((uint8_t*) buffer) = value;
      buffer += sizeof(uint8_t);
    }
  }
  else
  {
    struct open_file* file_desc = get_open_file (thread_current (), fd);
    if (file_desc == NULL) // File not open
      ret_value = -1;
    else
    {
      struct file* file = file_desc->file;
      ret_value = file_read (file, buffer, length);
    }
  }

  lock_release (&file_system_lock);
  return ret_value;
}

int
write (void)
{
  int fd = get_int ((int**) &stack_pointer);
  void* buffer = get_void_pointer ((void***) &stack_pointer);
  unsigned length = get_int ((int**) &stack_pointer);
  int ret_value = length;
  lock_acquire (&file_system_lock);

  if (fd == 1)
    putbuf (buffer, length);
  else
  {
    struct open_file* file_desc = get_open_file (thread_current (), fd);
    if (file_desc == NULL) // File not open
      ret_value = -1;
    else // actual write
    {
      struct file* file = file_desc->file;
      ret_value = file_write (file, buffer, length);
    }
  }

  lock_release (&file_system_lock);
  return ret_value;
}

void
seek (void)
{
  int fd = get_int ((int**) &stack_pointer);
  unsigned position = get_int ((int**) &stack_pointer);
  lock_acquire (&file_system_lock);
  struct open_file* file_desc = get_open_file (thread_current (), fd);
  if (file_desc != NULL)
  {
    struct file* file = file_desc->file;
    file_seek (file, position);
  }
  lock_release (&file_system_lock);
}

unsigned
tell (void)
{
  int fd = get_int ((int**) &stack_pointer);
  int ret_value = 0;
  lock_acquire (&file_system_lock);
  struct open_file* file_desc = get_open_file (thread_current (), fd);
  if (file_desc == NULL) // File not open
    ret_value = 0;
  else // actual write
  {
    struct file* file = file_desc->file;
    ret_value = file_tell (file);
  }
  lock_release (&file_system_lock);
  return ret_value;
}

void
close (void)
{
  int fd = get_int ((int**) &stack_pointer);
  struct open_file* file_desc = get_open_file (thread_current (), fd);
  if (file_desc != NULL)
  {
    list_remove (&file_desc->thread_elem);
    file_close (file_desc->file);
    free (file_desc);
  }
}

void*
get_void_pointer (void*** esp)
{
  validate_address (stack_pointer);
  void* ret = **esp;
  (*esp)++;
  validate_address (ret);
  return ret;
}
char*
get_char_pointer (char*** esp)
{
  validate_address (stack_pointer);
  char* ret = **esp;
  (*esp)++;
  validate_address (ret);
  return ret;
}

int
get_int (int **esp)
{
  validate_address (stack_pointer);
  int ret = **esp;
  (*esp)++;
  return ret;
}

void
validate_address (void *address)
{
  if (address == NULL ||
      is_kernel_vaddr (address) /*Accessing kernel address*/ ||
      pagedir_get_page (thread_current ()->pagedir, address) == NULL) exit(-1);
}
