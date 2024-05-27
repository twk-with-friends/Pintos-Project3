#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "kernel/stdio.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
#define STDIN_fileNO 0
#define STDOUT_fileNO 1

void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(tid_t pid);

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	int syscall_num = f->R.rax;

	check_address(f->rsp);

	switch (syscall_num)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f-> R.rsi);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:	
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		thread_exit();
	}
	// thread_exit ();
}

void check_address(void *addr)
{
	// NULL 포인터인지 체크 NULL 이면 EXIT
	if (addr == NULL)
		exit(-1);
	// 포인터가 USER 영역인지 체크 커널이면 EXIT
	if (!is_user_vaddr(addr))
		exit(-1);
	// 현재 스레드의 페이지 맵 레벨 4(pml4)를 확인하여 주어진 주소에 대한 페이지가 있는지 확인하는 pml4_get_page 함수를 호출 만약 해당 주소에 대한 페이지가 없다면 EXIT
	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *cur = thread_current (); 
	printf("%s: exit(%d)\n" , cur -> name , status);
	thread_exit();
}

int exec(const char *cmd_line)
{
}

int wait(tid_t pid)
{
}

tid_t fork(const char *thread_name, struct intr_frame *f)
{
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file)
{
	check_address(file);

	printf("=================================> file : %s\n", file);

	struct file *open_file = filesys_open(file);

	if (open_file == NULL)
		return -1;

	int fd = process_add_file(open_file);

    if (fd == -1)
        file_close(open_file);

	return fd;
}

int filesize(int fd)
{	
	if (fd < 2)
		return -1;
	
	struct file *file = process_get_file(fd);

	if (file == NULL)
		return -1;
	
	file_length(file);
}

int read(int fd, void *buffer, unsigned size)
{
	if (fd < 2)
		return -1;
	check_address(buffer);

	int byte;
	unsigned char *buf = buffer;
	struct file *file = process_get_file(fd);

	if(file == NULL)
		return -1;
	
	if (fd == STDIN_fileNO){
		char *input;

		for (int i = 0 ; i < size ; i++){
			input = input_getc();
			if (input == "\n")
				break;
			*buf = input;
			buf++;
			byte++;
		}
	}
	else{
		byte = file_read(file, buffer, size);
	}
	return byte;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);

	if (fd == STDIN_fileNO)
	{
		return -1;
	}

	if (fd == STDOUT_fileNO)
	{
		putbuf(buffer, size);
		return size;
	}

	int byte;
	struct file *file = process_get_file(fd);

	if(file == NULL)
		return -1; 
	
	return (int)file_write(file, buffer, size);
}

void seek(int fd, unsigned position)
{
	if (fd < 2)
		return -1;
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return -1;
	file_seek(file, position);
}

unsigned
tell(int fd)
{
	if (fd < 2)
		return -1;
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return -1;
	return file_tell(file);
}

void close(int fd)
{	
	struct file *file = process_get_file(fd);
	if (file == NULL){
		exit(-1);
	}

	printf("!!!!!!!!");	
	file_close(file);
	process_close_file(fd);
}
