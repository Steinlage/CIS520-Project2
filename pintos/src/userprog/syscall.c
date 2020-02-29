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

void halt (void)
{
  shutdown_power_off();
}

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

void check_address(void *addr)
{
  if (!is_user_vaddr(addr)) {
    exit(-1);
  }
}

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

// bool create (const char *file, unsigned initial_size) {

// }

// int write (int fd, const void *buffer, unsigned size) {
//   if (fd == STDOUT_FILENO) {
    
//   }
// }

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

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
  if (file == NULL) {
    exit(-1);
  }
  else {
    return filesys_create(file, initial_size);
  }
}

bool remove (const char *file) {
  return filesys_remove(file);
}

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
      // lock_release(&filesys_lock);
      // exit(-1);
      write_bytes = 0;
    }
  }
  lock_release(&filesys_lock);
  return write_bytes;
}

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
    // lock_acquire(&filesys_lock);
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
      // cur->next_fd++;
    }
    else{
      fd = -1;
    }
    // lock_release(&filesys_lock);
  }
  lock_release(&filesys_lock);
  return fd;
}
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

int
filesize(int fd)
{
  int size;
  struct file* read_file = thread_current()->fdt[fd];

  size = file_length(read_file);
  return size;
}
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

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

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
      /* check argument if bad address */
      check_address((void *)(p+1));
      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      get_argument(f->esp, arg, count); //Copy arguments on user stack at kernel

      ptemp_1 = (int *)arg[0];
      // printf("%s\n", thread_current()->name);
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
      // printf("current pid: %d\n", thread_current()->tid);
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

      // printf("write finish\n");
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
  // printf("%d\n", *(uint32_t *)(f->esp));
  // printf ("system call!\n");
  // thread_exit ();
}
