#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>
#include "devices/input.h"
#include "threads/malloc.h"

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

// Calls "shutdown_power_off"
void halt (void)
{
  shutdown_power_off();
}

// Terminates user program and sends status code to kernel. A code of 0 indicates a success
// and a non-0 code indicates an error.
void exit (int status)
{
  thread_current()->exit_status = status;

  int i;
  for (i = 3; i < 128; i++) {
      if (thread_current()->fdt[i] != NULL) {
          close(i);
      }
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

// Ensures that the given virtual memory address is in user space, as opposed to kernel
// space.
void check_address(void *addr)
{
  if (!is_user_vaddr(addr)) {
    exit(-1);
  }
}

// Takes inputs, "esp", "arg" and "count". Creats a temporary "esp" and sets its value to
// the value of "esp". Increments the value of "temp_esp" by 4, checks the address of
// "temp_esp" and sets the arguement value at the index to temp_esp's value casted as an int
// from 0 to "count"
void
get_argument(void *esp, int *arg, int count)
{
  void *temp_esp;
  temp_esp = esp;
  int i;
  for (i=0;i<count;i++)
  {
    temp_esp = temp_esp + 4;
    check_address(temp_esp);
    arg[i]= (int)temp_esp;
  }
}

// Takes an input value from the commmand line (cmd_line). Creates a new process id called "child_pid"
// sets its value to the value of "process_execute()" called on "cmd_line". Next a new thread is
// created called "child_proc". The value here is set to the call of "get_child_process()" on
// "child_proc" cast as an int. Next we check if the value of "child_proc" is null, meaning there is
// no processes for it. If so, -1 is returned. Otherwise, "load_flag" is called on "child_proc" and
// if it's value is 1, then "child_pid" is returned. Otherwise, -1 is returned.
pid_t exec (const char *cmd_line) {
  pid_t child_pid = (pid_t)process_execute(cmd_line);
  struct thread *child_proc = get_child_process((int)child_pid);

  if(child_proc ==NULL){
    return -1;
  }
  else{
    if(child_proc->load_flag ==1){
      return child_pid;
    }
    else{ //load fail
      return -1;
    }
  }
}

// Takes an input value of "pid" a process id. Returns the value of "process_wait()" called on "pid".
int wait (pid_t pid) {
  return process_wait(pid);
}

// Creates a new file called "file" initially with its "initial_size" bytes in size by calling "filesys_create" if the file is non-null.
// Otherwise it calls "exit" with the value of -1.
bool create (const char *file, unsigned initial_size) {
  if (file == NULL) {
    exit(-1);
  }
  else {
    return filesys_create(file, initial_size);
  }
}

// Removes the given "file" by calling "filesys_remove" on "file".
bool remove (const char *file) {
  return filesys_remove(file);
}

// Reads sizebytes from the file open as fdinto buffer. Returns the number of bytes
// actually read (0 at end of file), or -1 if the file could not be read (due to a condition
// other than end of file). .
int
read(int fd, void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);

  struct file* read_file;
  struct thread *cur = thread_current();
  int read_bytes = 0,  i;

  if(fd == 0){
    for(i=0;(unsigned)i<size;i++){
      *((char *)buffer+i) = input_getc();
    }
    read_bytes = size;
  }
  else{
    if(cur->fdt[fd]!=NULL){
      read_file = cur->fdt[fd];
      read_bytes = file_read(read_file, buffer, size);
    }
    else{
      read_bytes = -1;
    }
  }
  lock_release(&filesys_lock);
  return read_bytes;
}

// Writes the "size" of bytes from the "buffer" to the open file descriptor " fd". Returns the number
// of bytes actually written, which may be less than sizeif some bytes could not be written.
int
write(int fd, const void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);
  struct file* write_file;
  struct thread *cur = thread_current();
  int write_bytes = 0;

  if(fd == 1){
    putbuf(buffer, size);
    write_bytes = size;
  }
  else{
    if(cur->fdt[fd]!=NULL){
      write_file = cur->fdt[fd];
      write_bytes = file_write(write_file, buffer, size);
    }
    else{
      write_bytes = 0;
    }
  }
  lock_release(&filesys_lock);
  return write_bytes;
}

// Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd),
// or -1 if the file could not be opened.
int
open (const char *file)
{
  lock_acquire(&filesys_lock);
  struct thread *cur = thread_current();
  int fd, i;

  if (file == NULL) {
    fd = -1;
  }
  else {
    struct file* open_file = filesys_open (file);
    if(open_file != NULL){
      if(strcmp(cur->name,file)==0){
        file_deny_write(open_file);
      }
      cur->fdt[cur->next_fd] = open_file;
      fd = cur->next_fd;
      for (i=3;i<128;i++) {
        if (cur->fdt[i] == NULL) {
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

// Closes file descriptor (fd). Exiting or terminating a process implicitly closes all its
// open file descriptors, as if by calling this function for each one.
void
close (int fd)
{
  if (thread_current()->fdt[fd] == NULL) {
    // exit(-1);
  }
  else {
    file_close(thread_current()->fdt[fd]);
    thread_current()->fdt[fd] = NULL;
  }
}

// Returns the "size", in bytes, of the file open as fd (file descriptor)..
int
filesize(int fd)
{
  int size;
  struct file* read_file = thread_current()->fdt[fd];

  size = file_length(read_file);
  return size;
}

// Changes the next byte to be read or written in open file fd (file descriptor) to "position",
// expressed in bytes from the beginning of the file.
void
seek (int fd, unsigned position)
{
  struct thread *cur = thread_current();
  if(cur->fdt[fd]==NULL){
    exit(-1);
  }
  else{
    file_seek(cur->fdt[fd],position);
  }
}

// Returns the position of the next byte to be read or written in open
// file fd (file descriptor), expressed in bytes from the beginning of the file.
unsigned
tell (int fd)
{
  struct thread *cur = thread_current();
  if(cur->fdt[fd]==NULL){
    exit(-1);
  }
  else{
    return file_tell(cur->fdt[fd]);
  }
}

// Calls "lock_init" on the address of "filesys_lock". Then calls "intr_register_int"
// with the values of 0x30, 3, syscall_hanlder, and "syscall".
void
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Takes an input value of "f" and gets the "esp" from it and then uses that value to check the
// address. Creats a new int "SYS_NUM" and sets its value to f's esp value. Switches between
// different cases depending on f's esp value (SYS_NUM).
static void
syscall_handler (struct intr_frame *f) 
{
  int count;
  int *arg;
  int *p = f->esp;
  check_address(p);
  int SYS_NUM = (int)*p;

  switch (SYS_NUM)

  {
    int *ptemp_1;
    int *ptemp_2;
    int *ptemp_3;
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_address((void *)(p+1)); //Checks for a bad address
      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];

      exit(*ptemp_1);
      free(arg);
      break;
    case SYS_EXEC:
      check_address((void *)(p+1));
      check_address((void *)*(p+1));
      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];
      f->eax = exec((const char *)*ptemp_1);
      free(arg);
      break;
    case SYS_WAIT:
      check_address((void *)(p+1));
      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];

      if((int)*ptemp_1==-1){
        f->eax = -1;
      }
      else{
        f->eax = wait((int)*(ptemp_1));
      }
      free(arg);
      break;
    case SYS_CREATE:
      check_address((void *)(p+1));
      check_address((void *)(p+2));
      check_address((void *)*(p+1));
      count = 2;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];
      ptemp_2 = (int *)arg[1];

      f->eax = create((const char *)*ptemp_1, (unsigned int)*ptemp_2);
      free(arg);
      break;
    case SYS_REMOVE:
      check_address((void *)(p+1));
      check_address((void *)*(p+1));
      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];

      f->eax = remove((const char *)*(p+1));
      free(arg);
      break;
    case SYS_OPEN:
      check_address((void *)(p+1)); // arg0
      check_address((void *)*(p+1)); // file_name

      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];

      f->eax = open((const char *)*ptemp_1); //save return value of sys_open at eax register
      free(arg);
      break;
    case SYS_FILESIZE:
      check_address((void *)(p+1)); //arg0

      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];

      f->eax = filesize(*ptemp_1); //save return value of sys_filesize at eax register
      free(arg);
      break;
    case SYS_READ:
      check_address((void *)(p+3)); //argument size
      check_address((void *)(p+2));
      check_address((void *)(p+1));
      check_address((void *)*(p+2)); //argument *buffer

      count = 7;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];
      ptemp_2 = (int *)arg[1];
      ptemp_3 = (int *)arg[2];

      f->eax = read((int)*ptemp_1,(void *)*ptemp_2,(unsigned int)*ptemp_3); //save return value of sys_read at eax register
      free(arg);
      break;
    case SYS_WRITE:
      check_address((void *)(p+1));
      check_address((void *)(p+2));
      check_address((void *)(p+3));
      check_address((void *)*(p+2));

      count = 3;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel
      ptemp_1 = (int *)arg[0];
      ptemp_2 = (int *)arg[1];
      ptemp_3 = (int *)arg[2];

      f->eax = write((int)*ptemp_1,(const void*)*ptemp_2,(unsigned int)*ptemp_3);//save return value of sys_read at eax register

      free(arg);
      break;
    case SYS_SEEK:
      check_address((void *)(p+1));
      check_address((void *)(p+2));

      count = 2;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel
      ptemp_1 = (int *)arg[0];
      ptemp_2 = (int *)arg[1];

      seek((int)*ptemp_1,(unsigned int)*ptemp_2);

      free(arg);
      break;
    case SYS_TELL:
      check_address((void *)(p+1));

      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel
      ptemp_1 = (int *)arg[0];

      f->eax = tell((int)*ptemp_1);
      free(arg);
      break;
    case SYS_CLOSE:
      check_address((void *)(p+1)); // arg0

      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];

      close(*ptemp_1); //save return value of sys_open at eax register
      free(arg);
      break;
  }
}
