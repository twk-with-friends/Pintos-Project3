#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "kernel/stdio.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "vm/vm.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
struct lock filesys_lock;

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
int fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(int pid);

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);
	lock_init(&filesys_lock);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset){
	// Fail : map to i/o console, zero length, map at 0, addr not page-aligned
	if(fd == 0 || fd == 1 || length == 0 || addr == 0 || pg_ofs(addr) != 0 || offset > PGSIZE)
		return NULL;

	// Find file by fd
	struct file *file = process_get_file(fd);	

	// Fail : NULL file, file length is zero
	if (file == NULL || file_length(file) == 0)
		return NULL;

	return do_mmap(addr, length, writable, file, offset);
}
void
do_munmap (void *addr) {
	struct thread *t = thread_current();
	struct page *page;

	page = spt_find_page(&t->spt, addr);
	//int prev_cnt = 0;
	int prev_cnt = page->page_cnt - 1; //if the file size is bigger than memmory space, first page of consecutive file-pages in memory is not the first page of the file.

	// Check if the page is file_page or uninit_page to be transmuted into file_page and then its consecutive
	while(page != NULL 
		&& (page->operations->type == VM_FILE 
			|| (page->operations->type == VM_UNINIT && page->uninit.type == VM_FILE))
		&& page->page_cnt == prev_cnt + 1){
		if(pml4_is_dirty(t->pml4, addr)){
			struct file *file = page->file.file;
			size_t length = page->file.length;
			off_t offset = page->file.offset;

			if(file_write_at(file, addr, length, offset) != length){
				// #ifdef DBG
				// TODO - Not properly written-back
			}
		}	

		prev_cnt = page->page_cnt;

		// removed from the process's list of virtual pages.
		// pml4_clear_page(thread_current()->pml4, page->va);
		// destroy(page);
		// free(page->frame);
		// free(page);
		//remove_page(page);
		spt_remove_page(&t->spt, page);

		addr += PGSIZE;
		page = spt_find_page(&t->spt, addr);
	}
}

static void
munmap (void* addr){
	do_munmap(addr);
}

static void munmap (void* addr);
/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	int syscall_num = f->R.rax;

	check_address(f->rsp);
	thread_current()->rsp = f->rsp;
	switch (syscall_num)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
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
	case SYS_MMAP:
        f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
        break;

    case SYS_MUNMAP:
        munmap(f->R.rdi);
        break;

    default:
        break;
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
	// if (pml4_get_page(thread_current()->pml4, addr) == NULL)
	// 	exit(-1);
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *cur = thread_current (); 
	cur->exit_status = status;
	printf("%s: exit(%d)\n" , cur -> name , status);
	thread_exit();
}

int exec(const char *cmd_line)
{
		check_address(cmd_line);

		char *file_name = palloc_get_page(PAL_ZERO);

		if(file_name == NULL)
			exit(-1);
		
		strlcpy(file_name, cmd_line, PGSIZE);

		if(process_exec(file_name) == -1)
			exit(-1);
}

int wait(int pid)
{
	return process_wait(pid);

}

int fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
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

	struct file *open_file = filesys_open(file);

	if (open_file == NULL)
		return -1;

	if(strcmp(thread_name(), file) == 0) {
		file_deny_write(open_file);
	}

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
		struct page *page = spt_find_page(&thread_current()->spt, buffer);

		if (page != NULL && !page->writable)
			exit(-1);

		lock_acquire(&filesys_lock);
		byte = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return byte;
}

int write(int fd, const void *buffer, unsigned size) {
    check_address(buffer);
    if (fd == STDIN_fileNO) {
        return -1;
    }

    if (fd == STDOUT_fileNO) {
        putbuf(buffer, size);
        return size;
    }

    struct file *file = process_get_file(fd);
    if (file == NULL) {
        return -1;
    }

    int byte;

    lock_acquire(&filesys_lock);
    byte = (int)file_write(file, buffer, size);
    lock_release(&filesys_lock);

    return byte;
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
	
	file_close(file);
	process_close_file(fd);
}