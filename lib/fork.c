// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	pte_t pte = uvpt[PGNUM(addr)], pde = uvpd[PDX(addr)];
	if (!( (err & FEC_WR) && (pte & PTE_COW) ))
		// should I check for present?
		panic("pgfault error: the faulting page is not copy-on-write.");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
	envid_t curenvid = sys_getenvid(); // WHY:three system call ???
	// envid_t curenvid = thisenv->env_id; // WHY: this not work ?
	// cprintf("[[[[[[curenvid %d %d]]]]]\n", curenvid, sys_getenvid());

	r = sys_page_alloc(curenvid, (void*)PFTEMP, PTE_P | PTE_U | PTE_W);
	if (r < 0) panic("pgfault error: sys_page_alloc failed");

	void *roundAddr = ROUNDDOWN(addr, PGSIZE);
	memcpy((void*)PFTEMP, roundAddr, PGSIZE);
	r = sys_page_map(curenvid, (void*)PFTEMP, curenvid, roundAddr,
				PTE_P | PTE_U | PTE_W);
	if (r < 0) panic("pgfault error: sys_page_map failed");

	r = sys_page_unmap(curenvid, (void*)PFTEMP);
	if (r < 0) panic("pgfault error: sys_page_unmap failed");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	void* addr = (void*) (pn * PGSIZE);
	pte_t pte = uvpt[PGNUM(addr)];
	envid_t curenvid = sys_getenvid();
	if (pte & PTE_SHARE) {
		if ((r = sys_page_map(curenvid, addr, envid, addr, pte & PTE_SYSCALL)) < 0)
			return r;
	}
	else if ((pte & PTE_COW) || (pte & PTE_W)) {
		r = sys_page_map(curenvid, addr, envid, addr, PTE_P | PTE_U | PTE_COW);
		if (r < 0) return r;
		r = sys_page_map(curenvid, addr, curenvid, addr, PTE_P | PTE_U | PTE_COW);
		if (r < 0) return r;
	}
	else {
		r = sys_page_map(curenvid, addr, envid, addr, PTE_P | PTE_U);
		if (r < 0) return r;
	}
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	int r;
	set_pgfault_handler(pgfault);

	envid_t envid = sys_exofork();
	if (envid < 0) panic("fork error: sys_exofork failed");
	if (envid == 0) { // child
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	else { // parent
		// not UTOP, becasue UXSTACK should be copied
		for (uint32_t i = 0; i < USTACKTOP; i += PGSIZE) {
			if ((uvpd[PDX(i)] & PTE_P) && (uvpt[PGNUM(i)] & PTE_P) && (uvpt[PGNUM(i)] & PTE_U)) {
				r = duppage(envid, PGNUM(i));
				if (r < 0) panic("fork error: duppage failed %e", r);
			}
		}
		r = sys_page_alloc(envid, (void*)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W);
		if (r < 0) panic("fork error: sys_page_alloc failed");

		extern void _pgfault_upcall();
		sys_env_set_pgfault_upcall(envid, _pgfault_upcall);

		r = sys_env_set_status(envid, ENV_RUNNABLE);
		if (r < 0) panic("fork error: sys_env_set_status failed");

		return envid;
	}
}

// Challenge!
int
sfork(void)
{
	int r;
	set_pgfault_handler(pgfault);

	envid_t envid = sys_exofork(), curenvid = sys_getenvid();
	if (envid < 0) panic("fork error: sys_exofork failed");
	if (envid == 0) { // child
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	else { // parent
		// not UTOP, becasue UXSTACK should be copied
		for (uint32_t i = 0; i < USTACKTOP - PGSIZE; i += PGSIZE) {
			if ((uvpd[PDX(i)] & PTE_P) && (uvpt[PGNUM(i)] & PTE_P) && (uvpt[PGNUM(i)] & PTE_U)) {
				pte_t pte = uvpt[PGNUM(i)];
				if (pte & PTE_COW) { // we need to make it writable
					r = sys_page_alloc(curenvid, (void*)PFTEMP, PTE_P | PTE_U | PTE_W);
					if (r < 0) panic("sfork error: %e", r);
					memcpy((void*)PFTEMP, (void*)i, PGSIZE);
					r = sys_page_map(curenvid, (void*) PFTEMP, curenvid, (void*) i, PTE_P | PTE_U | PTE_W);
					if (r < 0) panic("sfork error: %e", r);
					r = sys_page_unmap(curenvid, (void*) PFTEMP);
					if (r < 0) panic("sfork error: %e", r);
				}
				r = sys_page_map(curenvid, (void*) i, envid, (void*) i, PTE_P | PTE_U | PTE_W);
				if (r < 0) panic("sfork error: %e", r);
			}
		}
		// user stack
		void *va = (void*)(USTACKTOP - PGSIZE);
		r = sys_page_map(curenvid, va, envid, va, PTE_P | PTE_U | PTE_COW);
		if (r < 0) panic("sfork error: %e", r);
		r = sys_page_map(curenvid, va, curenvid, va, PTE_P | PTE_U | PTE_COW);
		if (r < 0) panic("sfork error: %e", r);

		// user exception stack
		r = sys_page_alloc(envid, (void*)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W);
		if (r < 0) panic("fork error: sys_page_alloc failed");

		extern void _pgfault_upcall();
		sys_env_set_pgfault_upcall(envid, _pgfault_upcall);

		r = sys_env_set_status(envid, ENV_RUNNABLE);
		if (r < 0) panic("fork error: sys_env_set_status failed");

		return envid;
	}
}
