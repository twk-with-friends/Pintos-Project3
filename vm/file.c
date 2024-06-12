/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	struct uninit_page *uninit = &page->uninit;
	// vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* Set up the handler */
	page->operations = &file_ops;

	memset(uninit, 0, sizeof(struct uninit_page));

	struct lazy_load_info *info = (struct lazy_load_info *)aux;
	struct file_page *file_page = &page->file;
	file_page->file = info->file;
	file_page->length = info->page_read_bytes;
	file_page->offset = info->offset;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;

	ASSERT(page->frame->kva == kva); // #ifdef DBG check

	void *addr = page->va;
	//struct thread *t = thread_current();

	//aren't these already set in vm_do_claim_page?
	//page->frame->kva = kva; 
	//pml4_set_page(t->pml4, addr, kva, true); // writable true, as we are writing into the frame

	struct file *file = file_page->file;
	size_t length = file_page->length;
	off_t offset = file_page->offset;

	if(file_read_at(file, kva, length, offset) != length){
		// TODO - Not properly written-back
	}
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	void *addr = page->va;
	struct thread *t = thread_current();

	if(pml4_is_dirty(t->pml4, addr)){
		struct file *file = file_page->file;
		size_t length = file_page->length;
		off_t offset = file_page->offset;
		void *kva = page->frame->kva;
		if(file_write_at(file, kva, length, offset) != length){
			// TODO - Not properly written-back
		}
	}

	// access to page now generates fault
	pml4_clear_page(t->pml4, addr);
	page->frame->page = NULL;
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	close(file_page->file);
}

bool
lazy_load_segment_for_file(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct lazy_load_info * lazy_load_info = (struct lazy_load_info *)aux;
	struct file * file = lazy_load_info->file;
	size_t page_read_bytes = lazy_load_info->page_read_bytes;
	size_t page_zero_bytes = lazy_load_info->page_zero_bytes;
	off_t offset = lazy_load_info->offset;

	file_seek(file, offset);

	//vm_do_claim_page(page);
	ASSERT (page->frame != NULL); 	//이 상황에서 page->frame이 제대로 설정돼있는가?
	void * kva = page->frame->kva;
	if (file_read(file, kva, page_read_bytes) != (int)page_read_bytes)
	{
		//palloc_free_page(page); // #ifdef DBG Q. 여기서 free해주는거 맞아?
		free(lazy_load_info);
		return false;
	}

	memset(kva + page_read_bytes, 0, page_zero_bytes);
	free(lazy_load_info);

	file_seek(file, offset); // may read the file later - reset fileobj pos

	return true;
}