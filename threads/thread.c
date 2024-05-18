#include "threads/thread.h"
#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/fixed_point.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);


struct list sleep_list;
struct list all_list;
static int64_t global_ticks;

int load_avg;

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

void thread_sleep(int64_t ticks);
void thread_awake(int64_t ticks);
void update_global_ticks();
bool sort_by_min_tick(struct list_elem *e,struct list_elem *min, void *aux );
void cal_priority(struct thread *);
void cal_recent_cpu(struct thread *);
void cal_load_avg(void);
void cal_decay(void);
void incre_recent_cpu(void);
void thread_set_nice (int);
int thread_get_nice (void);
int thread_get_load_avg (void);
int thread_get_recent_cpu (void);
/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	// 글로벌 디스크립터 테이블 (세그리먼트 기반의 메모리 관리에서 중요한 역할)
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* 전역 컨테스트 초기화 */
	lock_init (&tid_lock); // 스레드 ID를 할당할 때 동시성 문제를 방지하기 위한 락
	list_init (&ready_list);
	list_init (&destruction_req);
	list_init (&sleep_list);
	list_init (&all_list);

	global_ticks = INT64_MAX;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT); // 우선순위를 기본값으로 설정
	list_push_back(&all_list, &initial_thread->a_elem);	
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid (); // 고유 tid를 할당
	initial_thread->wakeup_tick = 0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started; // 세마포어 구조체 선언
	sema_init (&idle_started, 0); // 세마포어를 초기화
	thread_create ("idle", PRI_MIN, idle, &idle_started);
	load_avg = LOAD_AVG_DEFAULT;
	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread) 
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE) //선점형 스케쥴링 구현
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL); // 함수 포인터가 유효한지

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO); // 페이지 할당자를 통해 메모리를 할당하고 할당된 메모리를 0으로
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	/* 쓰레드의 컨텍스트(상태)를 설정*/
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG; 
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	thread_unblock (t);
	if(name != "idle")
		list_push_back(&all_list, &t->a_elem);
	// max_priority();
	struct thread *cur = running_thread();
	if (cur->priority < priority)
	{
		thread_yield();
	}
	
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
/* 쓰레드를 차단 상태로 만나고 스케쥴러를 호출해서 다음 쓰레드로 전환하는 작업*/

// 1.sleep으로 변경
// 2.다음 실행할 thread 선정
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED; 
	schedule (); // 스케쥴러를 호출하여 새로운 쓰레드를 선택하고 실행 -> 다음 쓰레드를 선택하기 위해 스케쥴러 호출
}

/* 차단된 스레드 T를 준비-실행 상태로 전환합니다.
   T가 차단되지 않은 상태라면 이는 오류입니다. (실행 중인 스레드를 준비 상태로 만들기 위해서는 thread_yield()를 사용하세요.)

   이 함수는 실행 중인 스레드를 선점하지 않습니다. 이는 중요할 수 있습니다: 호출자가 인터럽트를 직접 비활성화한 경우,
   스레드를 원자적으로 차단 해제하고 다른 데이터를 업데이트할 수 있기를 기대할 수 있습니다. */
 
 /* 차단 상태의 쓰레드를 준비 상태로 변경하고 준비 리스트에 추가*/

 // block -> read로 전달한 thread 상태 변경
 // ready list에 넣는다.
 // 단 block list에서 제거하지 않는다.
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	// list_push_back (&ready_list, &t->elem);
	// 우선순위 기반으로 정렬한다
	list_insert_ordered(&ready_list, &t-> elem, cmp_priority, NULL);
	t->status = THREAD_READY;

	intr_set_level (old_level); // 인터럽트 레벨 복원
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	list_remove(&thread_current()->a_elem);
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_insert_ordered(&ready_list, & curr-> elem, cmp_priority, NULL);
	do_schedule (THREAD_READY);                          
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if (thread_mlfqs)
    return;
	thread_current ()->init_priority = new_priority;
	return_priority();
	max_priority();
}

/* Returns the current thread's priority. */
int 
thread_get_priority (void) {
	enum intr_level old_level = intr_disable ();
	int get_priority = thread_current ()->priority;
	intr_set_level (old_level);
	return get_priority;
}

void
thread_set_nice (int nice UNUSED) 
{ // 현재 스레드의 nice 값을 새 값으로 설정
  enum intr_level old_level = intr_disable ();
  thread_current ()->nice = nice;
  cal_priority (thread_current ());
  max_priority ();
  intr_set_level (old_level);
}

int
thread_get_nice (void) 
{ // 현재 스레드의 nice 값을 반환
  enum intr_level old_level = intr_disable ();
  int nice = thread_current ()-> nice;
  intr_set_level (old_level);
  return nice;
}

int
thread_get_load_avg (void) 
{ // 현재 시스템의 load_avg * 100 값을 반환
  enum intr_level old_level = intr_disable ();
  int load_avg_value = fp_to_int_round (mult_mixed (load_avg, 100));
  intr_set_level (old_level);
  return load_avg_value;
}

int
thread_get_recent_cpu (void) 
{ // 현재 스레드의 recent_cpu * 100 값을 반환
  enum intr_level old_level = intr_disable ();
  int recent_cpu= fp_to_int_round (mult_mixed (thread_current ()->recent_cpu, 100));
  intr_set_level (old_level);
  return recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL); // 쓰레드 포인터가 유효
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX); // 우선순위가 유효한 범위 내인지
	ASSERT (name != NULL); // 쓰레드 이름이 유효

	memset (t, 0, sizeof *t); // 쓰레드 구조체 기본값 설정 
	t->status = THREAD_BLOCKED; // 실행준비 X
	strlcpy (t->name, name, sizeof t->name); 
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->wait_on_lock = NULL;
	t->priority = priority;
	t->init_priority = priority;
	t->nice = NICE_DEFAULT;
  	t->recent_cpu = RECENT_CPU_DEFAULT;
	list_init(&t->donation);
	t->magic = THREAD_MAGIC;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
   /* 쓰레드간 문맥 전환 */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first4 restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
/* 스케쥴링 루틴을 수행 현재 실행중인 스레드 상태 변경, 스케쥴러를 호출해서 다음에 실행한 스레드를 선택 후 실행*/
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

/* 스케쥴러가 다음에 실행한 스레드를 선택하고, 필요한 경우 스레드 컨텍스트 전환*/
static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		   /* 현재 스레드가 종료 상태고 초기 스레드가 아닌경우 현재 쓰레드를 destruction_req에 추가 */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	} 
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

void update_global_ticks()
{
	struct list_elem *min_tick_e = list_begin(&sleep_list);
	struct thread *min_tick_thread = list_entry(min_tick_e, struct thread, elem);

	global_ticks = min_tick_thread->wakeup_tick;
}

/*
1. 현 스레드를 sleep으로 변경
2. global tick 변경
3. 다음 실행할 스레드 선정
*/
void thread_sleep(int64_t ticks)
{
    struct thread *cur = thread_current();

	ASSERT (!intr_context ());
    ASSERT(cur != idle_thread);

	if (cur == idle_thread) {
		return ;
	}

	enum intr_level old_level = intr_disable();

	cur->wakeup_tick = ticks;
	list_insert_ordered(&sleep_list, &cur->elem, sort_by_min_tick, NULL);

	update_global_ticks();
	// 1. sleep으로 변경
	// 2. 다음 실행할 thread 선정(schedule)
	thread_block();
	intr_set_level(old_level);
}


bool sort_by_min_tick (struct list_elem *e,struct list_elem *min, void *aux)
{
	int64_t a = list_entry(e, struct thread, elem)->wakeup_tick;
	int64_t b = list_entry(min, struct thread, elem)->wakeup_tick;

	return a < b;
}

// 1. sleep list에서 tick만족한 것들은 깨운다.
// 1-1. sleep list에서 제거
// 1-2 ready 상태로 변경
// 1-3 ready list에 삽입
void thread_awake(int64_t ticks)
{
	// 최소 tick이 현 tick보다 크다.
	// 즉 wake할 스레드가 존재하지 않는다.
	if (global_ticks>ticks) {
		return;
	}

	enum intr_level old_level;

    old_level = intr_disable();

    while (!list_empty(&sleep_list))
    {
        struct list_elem *e = list_begin(&sleep_list);
        struct thread *t = list_entry(e, struct thread, elem);

		if (t->wakeup_tick > ticks) {
			break;
		}

		// sleep_list에서 제거한다
		struct list_elem *wakeup_target_e = list_pop_front(&sleep_list);
		struct thread *wakeup_target_thread = list_entry(wakeup_target_e, struct thread, elem);
		// 1. block -> ready로 전달한 thread 상태 변경
 		// 2. ready list에 넣는다.
		thread_unblock(wakeup_target_thread);
		update_global_ticks();
    }

    intr_set_level(old_level);
}

bool cmp_priority(struct list_elem *cur,struct list_elem *cmp, void *aux){
	int cur_priority = list_entry(cur, struct thread, elem)->priority;
	int cmp_priority = list_entry(cmp, struct thread, elem)->priority;

	return cur_priority > cmp_priority;
}

bool cmp_sema_priority(struct list_elem *cur,struct list_elem *cmp, void *aux){
	int cur_priority = list_entry(cur, struct thread, d_elem)->priority;
	int cmp_priority = list_entry(cmp, struct thread, d_elem)->priority;

	return cur_priority > cmp_priority;
}

void 
max_priority(void){
	if (list_empty(&ready_list))
	{
		return;
	}
	
	if(thread_current() == idle_thread){
		return;
	}
	int curr_priority = thread_current()->priority;
	list_sort(&ready_list, cmp_priority, NULL);

	struct list_elem *e= list_begin(&ready_list);
	struct thread *t = list_entry(e, struct thread, elem);
	
	if (curr_priority < t->priority){
		thread_yield();
	}
}

void
cal_priority(struct thread *cur_thread){
	if (cur_thread == idle_thread) 
    	return ;
  	// cur_thread->priority = fp_to_int (add_mixed (div_mixed (cur_thread->recent_cpu, -4), PRI_MAX - cur_thread->nice * 2));
	cur_thread->priority = PRI_MAX - fp_to_int(cur_thread->recent_cpu/4) - (cur_thread->nice*2);
}

void
cal_load_avg(void){
	int ready_threads;
  
  	if (thread_current () == idle_thread)
    	ready_threads = list_size (&ready_list);
  	else
    	ready_threads = list_size (&ready_list) + 1;

  	load_avg = add_fp (mult_fp (div_fp (int_to_fp (59), int_to_fp (60)), load_avg), mult_mixed (div_fp (int_to_fp (1), int_to_fp (60)), ready_threads));
}

void
cal_decay(void){
	return (2 * load_avg) / (2 * load_avg + 1);
}

void
cal_recent_cpu(struct thread *cur_thread){
	if (cur_thread == idle_thread) 	
		return ;
  	cur_thread->recent_cpu = add_mixed (mult_fp (div_fp (mult_mixed (load_avg, 2), add_mixed (mult_mixed (load_avg, 2), 1)), cur_thread->recent_cpu), cur_thread->nice);
}

void
incre_recent_cpu(void){
	struct thread *cur_thread = thread_current(); 

	if(cur_thread != idle_thread){
		cur_thread->recent_cpu = add_mixed(cur_thread->recent_cpu,1);
	}
}

void
recal_recent_cpu(void){
	struct list_elem *e;

	for( e = list_begin(&all_list) ; e != list_end(&all_list) ; e = list_next(e) ){
		struct thread *t = list_entry(e, struct thread, a_elem);
		cal_recent_cpu(t);
	}
}

void
recal_priority(void){
	struct list_elem *e;

	for(  e = list_begin(&all_list) ; e != list_end(&all_list) ; e = list_next(e) ){
		struct thread *t = list_entry(e, struct thread, a_elem);
		cal_priority(t);
	}
}

