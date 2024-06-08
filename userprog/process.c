#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef vm
#include "vm/vm.h"
#endif


static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
struct thread *get_child_process(int pid);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	char argv[] = "";
	char *name_file, *save_ptr;
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	name_file = strtok_r(file_name, " ", &save_ptr);
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	// tid = thread_create (name_file, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */

tid_t process_fork(const char *name, struct intr_frame *if_) {
    // 현재 스레드를 가져옵니다.
    struct thread *curr = thread_current();

    // 현재 스레드의 parent_frame에 if_의 내용을 복사합니다.
    memcpy(&curr->parent_frame, if_, sizeof(struct intr_frame));

    // 새로운 스레드를 생성합니다.
    tid_t pid = thread_create(name, PRI_DEFAULT, __do_fork, curr);
    if (pid == TID_ERROR) {
        return TID_ERROR;
    }

    // 자식 프로세스의 스레드를 가져옵니다.
    struct thread *child = get_child_process(pid);

    // 자식 프로세스가 준비될 때까지 대기합니다.
    sema_down(&child->child_sema);

    return pid;
}

 
#ifndef VM 
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
// 부모 프로세스의 페이지 테이블 항목을 자식 프로세스의 페이지 테이블에 복제하는 역할
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;
	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if is_kernel_vaddr(va) {
		return true;
	}
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL) {
		return false;
	}
	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL) {
		return false;
	}
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) { //aux는 부모 프로세스의 정보를 전달하는데 사용되는 매개변수
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent ->parent_frame; 
	bool succ = true;
	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame)); 
	if_.R.rax = 0;
	/* 2. Duplicate PT */
	current->pml4 = pml4_create(); // 자식 프로세스의 페이지 테이블 생성
	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if (current->pml4 == NULL)
		goto error;
	current->file_descriptor_table[0] = parent->file_descriptor_table[0];
	current->file_descriptor_table[1] = parent->file_descriptor_table[1];

	for (int i = 2; i < FDT_COUNT_LIMIT; i++) {
		struct file * f = parent->file_descriptor_table[i];
		if (f == NULL){
			continue;
		}
		current->file_descriptor_table[i] = file_duplicate(f);
	}
    
	current->fdidx = parent->fdidx;
	sema_up(&current->child_sema);

	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_); 
error:
	current->exit_status = TID_ERROR;
	sema_up(&current->child_sema);
	exit(TID_ERROR);
	// thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/* 현재 프로세스를 정리하고 새 실행 파일을 로드하며, 새 프로세스의 컨텍스트로 전환하는 책임이 있음 */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;
	/* We first kill the current context */
	// 현재 프로세스 리소스 해제 새 프로그램 로드하기 위한 준비
	process_cleanup ();
	/* And then load the binary */
	success = load (file_name, &_if);

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);
	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *child = get_child_process(child_tid);
    if (child == NULL)
        return -1;
 
    sema_down(&child->wait_sema);                                                                                                                                                                                                                       
 
    list_remove(&child->child_list_elem); 
 
    sema_up(&child->exit_sema); 
 
    return child->exit_status; 
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	for (int i = 2 ; i < FDT_COUNT_LIMIT ; i++ ){
		struct file *file = process_get_file(i);
		if (file == NULL){
			break;
		}
		close(i);
	}	
	palloc_free_multiple(curr->file_descriptor_table, FDT_PAGES);
	file_close(curr->running);
	process_cleanup ();
	sema_up(&curr->wait_sema);
	sema_down(&curr->exit_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
/* 
사용자 프로그램을 메모리에 로드
실행 파일을 메모리에 로드하고, 실행을 위한 준비 과정을 담당/ 파일의 유효성 검사, 메모리 할당, 세그먼트 로딩, 스택 설정 등의 작업을 표시 
*/
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	char *copy_file_name;
	char *f_name;
	char *token, *save_ptr;
	char *argv[128];
	int argc = 0;
	
	copy_file_name = palloc_get_page(0);
	if (copy_file_name == NULL)
		return false;
	strlcpy(copy_file_name, file_name, PGSIZE);

	f_name = strtok_r(copy_file_name, " ", &save_ptr);

	/* Allocate and activate page directory. */
	// 가상 주소를 물리 주소로 변환하는 과정의 최상위 테이블 / 가상 메모리의 주소 공간을 관리
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (f_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", f_name);
		goto done;
	}

	// ELF 헤더를 읽고, 유효성 검사 수행
	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	 for (char *token = strtok_r(file_name, " ", &save_ptr); token != NULL;
        token = strtok_r(NULL, " ", &save_ptr)) {
        argv[argc++] = token;
    }

	t->running = file; // 현재 스레드의 실행 중인 파일을 설정합니다.
 
    // file_deny_write(file);

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	put_stack(argv,argc,if_);

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
/* ELF 파일의 프로그램 헤더가 유효한 세그먼트를 설명하는지 검증*/
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	// 페이지 오프셋 일치 여부 검사
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	// 파일 범위 내에서의 p_offset 검사
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	// p_memsz와 p_filesz 비교
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	// 세그먼트가 비어있는지 아닌지 비교
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	// 가상 메모리 주소 범위 검사
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	// 커널 가상 주소 공간으로의 "wrap around"방지
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	// 페이징 0 매핑 금지
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
/* 
커널 모드에서 실행되며, 프로세스가 사용자 모드로 전환할 때 필요한 사용자 스택을 준비하는 역할
프로세스의 사용자 스택을 초기화하고, 필요한 메모리 페이지를 할당 및 매핑하는 과정을 담당
*/
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

 bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct load_aux *load_aux = (struct load_aux*)aux;
	struct file *file = load_aux->file;
	off_t offset = load_aux->offset;
	size_t read_bytes = load_aux->read_bytes;
    size_t zero_bytes = load_aux->zero_bytes;
	file_seek(file,offset);

	if (file_read(file, page->frame->kva, read_bytes) != (int)read_bytes) { 
		palloc_free_page(page->frame->kva);
        return false;
    }
    memset(page->frame->kva + read_bytes, 0, zero_bytes);
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct load_aux *load_aux = malloc(sizeof(struct load_aux));
		
		load_aux->file = file;
		load_aux->offset = ofs;
		load_aux->read_bytes = read_bytes;
		load_aux->zero_bytes = zero_bytes;

		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, load_aux)){
			free(load_aux);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;  // 오프셋(ofs) 갱신
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	if(vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1)){
		success = true;
		success = vm_claim_page(stack_bottom);
		
		if (success)	
			if_->rsp=USER_STACK;
	}

	return success;
}
#endif /* VM */


void
put_stack(char **argv, int argc, struct intr_frame *if_){
	int total_length = 0;
    int align_size;
    char *arg;

    // 1. 각 문자열을 스택에 푸시하고, 각 문자열의 길이를 계산
    for (int i = argc - 1; i >= 0; i--) {
        int length = strlen(argv[i]) + 1; // 널 문자 포함
        if_->rsp -= length;
        memcpy(if_->rsp, argv[i], length);
        argv[i] = if_->rsp; // 새로운 문자열 주소 업데이트
        total_length += length;

		// printf("Pushed \"%s\" to stack at %p\n", argv[i], (void *)if_->rsp);
    }

    // 2. 스택 포인터를 8의 배수로 정렬
    align_size = (8 - (total_length % 8)) % 8;
    if_->rsp -= align_size;
    memset(if_->rsp, 0, align_size);

	// printf("Aligned stack pointer by %d bytes to %p\n", align_size, (void *)if_->rsp);

    // 3. 각 문자열의 주소와 널 포인터를 스택에 푸시
    if_->rsp -= sizeof(char*); // 널 포인터 공간 확보
    *(char**)if_->rsp = 0; // 널 포인터 설정

    for (int i = argc - 1; i >= 0; i--) {
        if_->rsp -= sizeof(char*);
        *(char**)if_->rsp = argv[i];

		// printf("Pushed address of \"%s\" to stack at %p\n", argv[i], (void *)if_->rsp);
    }

    // 4. %rsi와 %rdi 설정
    if_->R.rsi = if_->rsp;
    if_->R.rdi = argc;

	// printf("Set rsi to %p and rdi to %d\n", (void *)if_->R.rsi, if_->R.rdi);

    // 5. 가짜 반환 주소 푸시
    if_->rsp -= sizeof(void*);
    *(void**)if_->rsp = 0; // 가짜 반환 주소 설정

	// printf("Pushed fake return address to %p\n", (void *)if_->rsp);
}

int process_add_file(struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx; 

	while (fdt[fd] != NULL && fd < FDT_COUNT_LIMIT) {
		fd++;
	}

	if (fd >= FDT_COUNT_LIMIT || fd < 2) {
		return -1;
	}

	t->fdidx = fd;
	fdt[fd] = file;

	return fd;
}

struct file *process_get_file(int fd)
{
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	if (fd < 2 || fd > FDT_COUNT_LIMIT)
		return NULL;
	
	struct file *file = fdt[fd];
	return file;
}

void process_close_file(int fd)
{
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	
	if (fd < 2 || fd > FDT_COUNT_LIMIT)
		return NULL;
	fdt[fd] = NULL;
}

// struct thread *get_child_process(int pid){
// 	struct thread *curr = thread_current();
// 	struct list get_list = curr -> child_list;

// 	for (struct list_elem *e = list_begin(&get_list); e != list_end(&get_list); e = list_next(e)){
// 		struct thread *t = list_entry(e, struct thread, child_list_elem);
// 		if (t->tid == pid) {
// 			return t;
// 		}
// 	}
// 	return NULL;
// }

struct thread *get_child_process(int pid) {
	struct thread *cur = thread_current();
	for (struct list_elem *e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)) {
		struct thread *t = list_entry(e, struct thread, child_list_elem);
		if (t->tid == pid)
			return t;
	}
	return NULL;
}