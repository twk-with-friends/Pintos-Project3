  /* vm.c: Generic interface for virtual memory objects. */

#include <string.h>
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "lib/round.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "lib/kernel/list.h"
#include "userprog/process.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
struct list frame_table;
struct list_elem *start;

void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	list_init(&frame_table);
	start = list_begin(&frame_table);
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
uint64_t hash_func (const struct hash_elem *e, void *aux);
bool less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void hash_action_destroy (struct hash_elem *e, void *aux UNUSED);
/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		struct page *page = malloc(sizeof (struct page));

		switch (VM_TYPE(type)){
			case VM_ANON:
				uninit_new(page, pg_round_down(upage), init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new(page, pg_round_down(upage), init, type, aux, file_backed_initializer);
				break;
			default:
				free(page);
				goto err;
		}
		
		page->writable = writable;
		if(!spt_insert_page(spt, page)){
			free(page);
			goto err;
		}
		return true;	
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* TODO: Fill this function. */
    struct page *page = (struct page *)malloc(sizeof(struct page));
    struct hash_elem *e;
    page->va = pg_round_down(va);
	// printf("====================\n");
	// printf("Claim va: %p\n", page->va);
    // struct hash_iterator it;
    // for (hash_first(&it, &spt->spt_hash); hash_next(&it);) {
    //     struct page *p = hash_entry(hash_cur(&it), struct page, hash_elem);
    //     printf("Page va: %p\n", p->va);
    // }
    e = hash_find(&spt->spt_hash, &page->hash_elem);
    free(page);
    return e != NULL ? hash_entry(e, struct page, hash_elem): NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct hash_elem *elem = hash_insert(&spt->spt_hash, &page->hash_elem);
	if(elem == NULL)
		succ = true;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	 /* TODO: The policy for eviction is up to you. */
	//FIFO
	struct list_elem *e = list_pop_front(&frame_table);
	struct frame *victim = list_entry(e, struct frame, frame_elem);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));
    frame->kva = palloc_get_page(PAL_USER);

    if (frame->kva == NULL) {
        frame = vm_evict_frame();
        frame->page = NULL;

        return frame;
    }

    list_push_back(&frame_table, &frame->frame_elem);
    frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    
	if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

	
    if (not_present) 
    {	
        /* TODO: Validate the fault */
		void *rsp = is_kernel_vaddr(f->rsp)?thread_current()->rsp:f->rsp;

		if (USER_STACK - 0x100000 <= addr && USER_STACK >= addr && rsp-8 <= addr)
			vm_stack_growth(pg_round_down(addr));
			
        page = spt_find_page(spt, addr);
        if (page == NULL)
            return false;
        if (write == true && page->writable == false) 
            return false;
        return vm_do_claim_page(page);
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);

	if (page == NULL) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	if (frame == NULL) {
		return false;
	}
	if (pml4_get_page (thread_current()->pml4, page->va) == NULL) {

		/* Set links */
		frame->page = page;
		page->frame = frame;
		/* TODO: Insert page table entry to map page's VA to frame's PA. */
		if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
			return false;
		}
	}
	swap_in (page, frame->kva);
	return true;
	// return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
		hash_init(&spt->spt_hash, hash_func, less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) {
    struct hash_iterator iter;
	struct hash *src_hash = &src->spt_hash;
    struct hash *dst_hash = &dst->spt_hash;
    hash_first (&iter, &src->spt_hash);

    while (hash_next (&iter)) {
        const struct page *p = hash_entry (hash_cur (&iter), struct page, hash_elem);
		enum vm_type type = p->operations->type;

		if(type == VM_UNINIT){
			struct uninit_page *uninit = &p->uninit;
			struct load_aux *load_aux =  (struct load_aux*)uninit->aux;

			struct load_aux *child_load_aux = malloc(sizeof(struct load_aux));
			memcpy(child_load_aux,load_aux,sizeof(struct load_aux));
			child_load_aux->file = file_duplicate(load_aux->file);
			
			vm_alloc_page_with_initializer(uninit->type,p->va,p->writable,uninit->init,child_load_aux);
			vm_claim_page(p->va);
		}else{
			vm_alloc_page(p->operations->type, p->va, p->writable); 
			vm_claim_page(p->va); 
			memcpy(p->va, p->frame->kva, PGSIZE);  
		}

    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, hash_action_destroy);
}

// hash 함수
uint64_t hash_func (const struct hash_elem *e, void *aux){
	const struct page *p = hash_entry(e,struct page, hash_elem);
	return hash_bytes(&p->va,sizeof(p->va));
}

bool less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux){
	const struct page *p_a = hash_entry(a, struct page, hash_elem);
	const struct page *p_b = hash_entry(b, struct page, hash_elem); 

	return p_a->va < p_b->va;
}

bool page_delete(struct hash *hash, struct page *page) {
    return !hash_delete(hash, &page->hash_elem) ? true : false;
}

void spt_destroy (struct hash_elem *e, void *aux UNUSED) {
    struct page *page = hash_entry(e, struct page, hash_elem);

    free(page);  
}

void hash_action_destroy (struct hash_elem *e, void *aux UNUSED) {
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);  
    free(page);  
}