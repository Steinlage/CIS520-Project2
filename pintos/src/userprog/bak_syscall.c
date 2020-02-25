#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

void
halt (void)
{
  shutdown_power_off();
}

void
exit (int status)
{
  thread_current()->exit_status = status;

  int i;
  for (i = 3; i < 128; i++)
    {
      if (thread_current()->fdt[i] != NULL)
        {
            close(i);
        }
    }

  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

pid_t
exec (const char *cmd_line)
{
  pid_t child_pid = (pid_t)process_execute(cmd_line);
  struct thread *child_proc = get_child_process((int)child_pid);

  if(child_proc ==NULL)
    {
      return -1;
    }
  else
    {
      if(child_proc->load_flag ==1)
        {
          return child_pid;
        }
      else
        {
          return -1;
        }
    }
}

int
wait (pid_t pid)
{
  return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size)
  {
    if (file == NULL)
      {
        exit(-1);
      }
    else
      {
        return filesys_create(file, initial_size);
      }
  }


bool
remove (const char *file)
{
  return filesys_remove(file);
}

int 
open (const char *file)
{
  lock_acquire(&filesys_lock);
  struct thread *cur = thread_current();
  int fd, i;

  if (file == NULL)
    {
      fd = -1;
    }
  else
    {
      struct file* open_file = filesys_open (file);

      if(open_file != NULL)
        {
          if(strcmp(cur->name,file)==0)
            {
              file_deny_write(open_file);
            }

          cur->fdt[cur->next_fd] = open_file;
          fd = cur->next_fd;

          for (i=3;i<128;i++)
            {
              if (cur->fdt[i] == NULL)
                {
                  cur->next_fd = i;
                  break;
                }
            }
        }
      else{
        fd = -1;
      }
    }
  lock_release(&filesys_lock);
  return fd;
}

int
filesize(int fd)
{
  int size;
  struct file* read_file = thread_current()->fdt[fd];

  size = file_length(read_file);
  return size;
}

int
read(int fd, void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);

  struct file* read_file;
  struct thread *cur = thread_current();
  int read_bytes = 0,  i;

  if(fd == 0)
    {
      for(i=0;(unsigned)i<size;i++)
        {
          *((char *)buffer+i) = input_getc();
        }
      read_bytes = size;
    }
  else
    {
      if(cur->fdt[fd]!=NULL)
        {
          read_file = cur->fdt[fd];
          read_bytes = file_read(read_file, buffer, size);
        }
      else
        {
          read_bytes = -1;
        }
    }
  lock_release(&filesys_lock);
  return read_bytes;
}

int 
write(int fd, const void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);
  struct file* write_file;
  struct thread *cur = thread_current();
  int write_bytes = 0;

  if(fd == 1)
    {
      putbuf(buffer, size);
      write_bytes = size;
    }
  else
    {
      if(cur->fdt[fd]!=NULL)
        {
          write_file = cur->fdt[fd];
          write_bytes = file_write(write_file, buffer, size);
        }
      else
        {
          write_bytes = 0;
        }
    }
  lock_release(&filesys_lock);
  return write_bytes;
}

void
seek (int fd, unsigned position)
{
  struct thread *cur = thread_current();
  if(cur->fdt[fd]==NULL)
    {
      exit(-1);
    }
  else
    {
      file_seek(cur->fdt[fd],position);
    }
}

unsigned
tell (int fd)
{
  struct thread *cur = thread_current();
  if(cur->fdt[fd]==NULL)
    {
      exit(-1);
    }
  else
    {
      return file_tell(cur->fdt[fd]);
    }
}

void
close (int fd)
{
  if (thread_current()->fdt[fd] != NULL)
    {
      file_close(thread_current()->fdt[fd]);
      thread_current()->fdt[fd] = NULL;
    }
}
