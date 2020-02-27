#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <lib/user/syscall.h>
#include <stdint.h>

void syscall_init (void);
//static void syscall_handler (struct intr_frame *);
static uint32_t* p_argv(void* addr);
//static void halt (void);
//static tid_t exec (const char *file);
//static int wait (tid_t pid);
//static int create (const char *file, unsigned initial_size);
//static int remove (const char *file);
//static int open (const char *file);
//static int filesize (int fd);
//static int read (int fd, void *buffer, unsigned size);
//static int write (int fd, const void *buffer, unsigned size);
//static void seek (int fd, unsigned position);
//static int tell (int fd);
//static void close (int fd);
static bool fd_validate(int fd);
static bool string_validate(const char* ptr);
static bool is_bad_pointer(const char* ptr);


#endif /* userprog/syscall.h */
