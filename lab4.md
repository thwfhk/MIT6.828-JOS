# Report for lab4

Wenhao Tang, 1800013088

选择做了challenge 6 (实现sfork)

[TOC]

## Part A: Multiprocessor Support and Cooperative Multitasking

### Exercise 1

> Exercise 1. Implement mmio_map_region in kern/pmap.c. To see how this is used, look at the beginning of lapic_init in kern/lapic.c.

```c
	size_t roundSize = ROUNDUP(size, PGSIZE);
	if (base + roundSize > MMIOLIM) panic("mmio_map_region: MMIO space run out.");
	boot_map_region(kern_pgdir, base, roundSize, pa, PTE_PCD | PTE_PWT | PTE_W);
	base = base + roundSize;
```

这部分代码将`[pa, pa+size)`映射到`[base, base+size)`，使用`boot_map_region`映射即可，注意判断越界、设置（由于是device不能缓存）和4KB对齐。

### Exercise 2

> Exercise 2. Read boot_aps() and mp_main() in kern/init.c, and the assembly code in kern/mpentry.S. Make sure you understand the control ﬂow transfer during the bootstrap of APs. Then modify your implementation of page_init() in kern/pmap.c to avoid adding the page at MPENTRY_PADDR to the free list, so that we can safely copy and run AP bootstrap code at that physical address.

之前basemem里除了第一个page以外都是free的，现在`MPENTRY_PADDR = 0x7000`处的这个page也不是free了，只要加上如下一句特判即可：

```c
		if (i * PGSIZE == MPENTRY_PADDR) continue;
```

#### Question 1

因为对于`kern/mpentry.S`来说，它被link到`KERNBASE`之上的地址，但是一开始却要运行在real mode下，load address是`MPENTRY_PADDR`，所以要使用`MPBOOTPHYS(s)`来算出s这个link address所对应的load address。而对于`boot/boot.S`，它的link address和load address是同一个，都是`0x7c00`，不需要再计算load address。

### Exercise 3

> Exercise 3. Modify mem_init_mp() (in kern/pmap.c) to map per-CPU stacks starting at KSTACKTOP, as shown in inc/memlayout.h. The size of each stack is KSTKSIZE bytes plus KSTKGAP bytes of unmapped guard pages.

```c
	for (int i = 0; i < NCPU; i++) {
		boot_map_region(
			kern_pgdir,
			KSTACKTOP - i * (KSTKSIZE + KSTKGAP) - KSTKSIZE,
			KSTKSIZE,
			PADDR(percpu_kstacks[i]),
			PTE_W | PTE_P);
	}
```

这里让我们把每个cpu的kernel stack映射到物理内存`percpu_kstacks[i]`处，kernel stack的虚拟内存地址在`memlayout.h`中有，`boot_map_region()`一下即可。

### Exercise 4

> Exercise 4. The code in trap_init_percpu() (kern/trap.c) initializes the TSS and TSS descriptor for the BSP. It worked in Lab 3, but is incorrect when running on other CPUs. Change the code so that it can work on all CPUs. (Note: your new code should not use the global ts variable any more.)

```c
	int i = cpunum();
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - i * (KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3) + i] = SEG16(STS_T32A, (uint32_t) (&thiscpu->cpu_ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + i].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0 + 0x08 * i);

	// Load the IDT
	lidt(&idt_pd);
```

这里让我们修改`trap_init_percpu()`函数，对于每个CPU都进行正确的设置（之前的实现只考虑了有一个CPU0）。首先将全局`ts`修改成`thiscpu->cpu_ts`，然后`esp0`设置成对应kernel stack地址，TSS descriptor按照代码注释要求设置，TSS selector也需要设置成每个CPU自己的。

### Exercise 5

> Exercise 5. Apply the big kernel lock as described above, by calling lock_kernel() and unlock_kernel() at the proper locations.

在lab4说明中那四条所说的位置加了`lock_kernel()`或`unclock_kernel`

#### Question 2

> It seems that using the big kernel lock guarantees that only one CPU can run the kernel code at a time. Why do we still need separate kernel stacks for each CPU? Describe a scenario in which using a shared kernel stack will go wrong, even with the protection of the big kernel lock.

问题在于我们是在`trap()`函数里申请的lock，然而在这之前CPU已经往kernel stack里push了SS, ESP, EFLAGS, CS, EIP, and an optional error code，然后`trapEntry.S`中软件又push了一些registers进去，所以每个CPU需要自己的kernel stack。

### Exercise 6

> Exercise 6. Implement round-robin scheduling in sched_yield() as described above. Don't forget to modify syscall() to dispatch sys_yield().

```c
	struct Env *cur = thiscpu->cpu_env;
	int index;
	if (cur) index = ENVX(cur->env_id);
	else index = NENV - 1;
	for (int i = (index + 1) % NENV; i != index; i = (i+1) % NENV) {
		if (envs[i].env_status == ENV_RUNNABLE) {
			env_run(&envs[i]);
			return;
		}
	}
	if (envs[index].env_status == ENV_RUNNABLE) {
		env_run(&envs[index]);
		return;
	}
	if (cur && cur->env_status == ENV_RUNNING) {
		env_run(cur); // 也需要env_run
		return;
	}
	// sched_halt never returns
	sched_halt();
```

这部分要实现round-robin调度算法，按照要求实现即可。注意一下绕圈的特判QwQ。

#### Question 3

> In your implementation of env_run() you should have called lcr3(). Before and after the call to lcr3(), your code makes references (at least it should) to the variable e, the argument to env_run. Upon loading the %cr3 register, the addressing context used by the MMU is instantly changed. But a virtual address (namely e) has meaning relative to a given address context--the address context speciﬁes the physical address to which the virtual address maps. Why can the pointer e be dereferenced both before and after the addressing switch?

因为`envs[]`数组在内核部分，这部分所有environments都是一样的。

#### Question 4

> Whenever the kernel switches from one environment to another, it must ensure the old environment's registers are saved so they can be restored properly later. Why? Where does this happen?

因为registers保存了程序运行的重要信息，所以需要保存下来。

`kern/trapEntry.S`中将registers信息push到了kernel stack上，然后`kern/trap.c`中`curenv->env_tf = *tf;`这条语句将`trapFrame`保存到了当前env的`envs[]`数组中的结构体里。

### Exercise 7

> Exercise 7. Implement the system calls described above in kern/syscall.c and make sure syscall() calls them. You will need to use various functions in kern/pmap.c and kern/env.c, particularly envid2env(). For now, whenever you call envid2env(), pass 1 in the checkperm parameter. Be sure you check for any invalid system call arguments, returning -E_INVAL in that case. Test your JOS kernel with user/dumbfork and make sure it works before proceeding.
>

这部分要实现`kern/syscall.c`的那几个函数`sys_exofork, sys_env_set_status, sys_page_alloc, sys_page_map, sys_page_unmap`。注释说明的很详细，注意各种错误条件。我遇到的一个坑是`syscall`的switch里忘return了。

具体内容见代码吧

## Part B: Copy-on-Write Fork

Part B要实现copy-on-write fork来解决fork效率低的问题。为此需要知道在write-protected pages上触发的page fault。JOS这里用了一种特殊的做法，让用户来写page fault handler。

PS：回顾一下，page fault会在present=0或者权限不够时被触发。

### Exercise 8

> Exercise 8. Implement the sys_env_set_pgfault_upcall system call. Be sure to enable permission checking when looking up the environment ID of the target environment, since this is a "dangerous" system call.

```c
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env *e;
	int ret = envid2env(envid, &e, 1);
	if (ret < 0) return ret;
	e->env_pgfault_upcall = func;
	return 0;
}
```

和exercise 7做的事情类似，实现`sys_env_set_pgfault_upcall`这个syscall。需要注意的是，user并不是使用这个syscall来直接注册user page fault handler的，而是exercise 11中的`set_pgfault_handler`函数。

### Exercise 9

> Exercise 9. Implement the code in page_fault_handler in kern/trap.c required to dispatch page faults to the user-mode handler. Be sure to take appropriate precautions when writing into the exception stack. (What happens if the user environment runs out of space on the exception stack?)

```c
		if (curenv->env_pgfault_upcall) {
		size_t size = sizeof(struct UTrapframe) + 4;
		uint32_t addr = tf->tf_esp - size;
		if (tf->tf_esp < UXSTACKTOP-PGSIZE || tf->tf_esp > UXSTACKTOP-1)
			addr = UXSTACKTOP - size;
		user_mem_assert(curenv, (void*)addr, size, PTE_W);

		struct UTrapframe *utf = (struct UTrapframe *) addr;
		utf->utf_fault_va = fault_va;
		utf->utf_err = tf->tf_err;
		utf->utf_regs = tf->tf_regs;
		utf->utf_eip = tf->tf_eip;
		utf->utf_eflags = tf->tf_eflags;
		utf->utf_esp = tf->tf_esp;

		tf->tf_esp = addr;
		tf->tf_eip = (uintptr_t) curenv->env_pgfault_upcall;
		env_run(curenv);
	}
```

这里要实现内核中`page_fault_handler`处理user page fault的部分，就是调用之前注册的`env_pgfault_upcall`函数。首先检查`env_pgfault_upcall`有没有，然后判断一下当前是否是page fault handler的递归调用。再用`user_mem_assert`检查一下是否有访问这段内存的权限。

然后set up user exception stack上的UTrapframe，并设置`curenv`的esp和eip，在user exception stack上运行user page fault handler.

### Exercise 10

> Exercise 10. Implement the _pgfault_upcall routine in lib/pfentry.S. The interesting part is returning to the original point in the user code that caused the page fault. You'll return directly there, without going back through the kernel. The hard part is simultaneously switching stacks and re-loading the EIP.

这里要实现`_pgfault_upcall`这个***用户级***包装函数，这个函数是page fault upcall的默认行为，在内部调用`_pgfault_handler`（就是user page fault handler），然后返回。

这个函数的目的是包装用户写的page fault handler，让用户不需要处理从user exception stack返回的问题。

需要注意的是我们是从user exception stack上返回，需要把esp和eip以及其他registers设置成user exception stack上的`UTrapframe`结构所存的东西。这里用了一个技巧，利用了exercise 9中空的4 bytes（空4 bytes是处理递归的page fault handler调用，第一个的话user exception stack本身前面就有空），把目标eip的值放进去，然后把目标esp修改为esp-4，这样最后一个`ret`之后取出的返回地址就是目标eip了。

```assembly
// LAB 4: Your code here.
	movl 0x30(%esp), %eax // trap-time esp
	subl $4, %eax // trap-time esp - 4
	movl %eax, 0x30(%esp)
	movl 0x28(%esp), %ebx // trap-time eip
	movl %ebx, (%eax) // 4 bytes preserved previously

	// Restore the trap-time registers.  After you do this, you
	// can no longer modify any general-purpose registers.
	// LAB 4: Your code here.
	addl $8, %esp
	popal

	// Restore eflags from the stack.  After you do this, you can
	// no longer use arithmetic operations or anything else that
	// modifies eflags.
	// LAB 4: Your code here.
	addl $4, %esp
	popfl

	// Switch back to the adjusted trap-time stack.
	// LAB 4: Your code here.
	popl %esp

	// Return to re-execute the instruction that faulted.
	// LAB 4: Your code here.
	ret
```

### Exercise 11

> Exercise 11. Finish set_pgfault_handler() in lib/pgfault.c.

这是一个***用户级***的函数，作用是设置user page fault handler，将它放在`_pgfault_handler`这个全局变量里，供`_pgfault_upcall`调用。

第一次调用它时要分配user exception stack，并使用`sys_env_set_pgfault_upcall`来注册exercise 10里写的`_pgfault_upcall`。

```c
void
set_pgfault_handler(void (*handler)(struct UTrapframe *utf))
{
	int r;

	if (_pgfault_handler == 0) {
		// First time through!
		// LAB 4: Your code here.
		int ret = sys_page_alloc(sys_getenvid(), (void*) (UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W);
		if (ret < 0) panic("set_pgfault_handler error: user exception stack alloc error");
		ret = sys_env_set_pgfault_upcall(sys_getenvid(), _pgfault_upcall);
		if (ret < 0) panic("set_pgfault handler error: set pgfault upcall error");
	}

	// Save handler pointer for assembly to call.
	_pgfault_handler = handler;
}
```

> Make sure you understand why user/faultalloc and user/faultallocbad behave differently.

`user/faultalloc`使用`	cprintf("%s\n", (char*)0xDeadBeef);`打印一个未分配的地址，而`user/faultallocbad`使用`	sys_cputs((char*)0xDEADBEEF, 4);`打印一个未分配的地址。两者的区别在于，`sys_cputs`直接检查当前进程是否有权限访问地址`0xdeadbeef`，没有的话就panic，不会触发page fault；而`cprintf`中途会触发page fault。

### Exercise 12

> Exercise 12. Implement fork, duppage and pgfault in lib/fork.c.

这里太坑了呜呜呜，debug了好久，结果发现是exercise 9写错了呜呜呜

没什么可说的，看代码吧。

## Part C: Preemptive Multitasking and Inter-Process communication (IPC)

### Exercise 13

> Exercise 13. Modify kern/trapentry.S and kern/trap.c to initialize the appropriate entries in the IDT and provide handlers for IRQs 0 through 15. Then modify the code in env_alloc() in kern/env.c to ensure that user environments are always run with interrupts enabled.
>
> Also uncomment the sti instruction in sched_halt() so that idle CPUs unmask interrupts.

类似lab3中初始化trap handlers的方式来初始化interrupt handler。需要注意的是`SETGATE`中要把所有的异常中断都变成interrupt gate（也就是会屏蔽其他interrupt），因为JOS中要求内核模式不能有interrupt。然后`env_alloc`中要开启interrupt：`	e->env_tf.tf_eflags = FL_IF;`。

现在运行`user/spin`的输出如下：

```
enabled interrupts: 1 2
[00000000] new env 00001000
I am the parent.  Forking the child...
[00001000] new env 00001001
I am the parent.  Running the child...
I am the child.  Spinning...
TRAP frame at 0xf02bc07c from CPU 0
  edi  0x00000000
  esi  0x00000000
  ebp  0xeebfdfd0
  oesp 0xefffffdc
  ebx  0x00000000
  edx  0xeebfde88
  ecx  0x0000001d
  eax  0x0000001d
  es   0x----0023
  ds   0x----0023
  trap 0x00000020 Hardware Interrupt
  err  0x00000000
  eip  0x00800064
  cs   0x----001b
  flag 0x00000282
  esp  0xeebfdfc8
  ss   0x----0023
[00001001] free env 00001001
I am the parent.  Killing the child...
[00001000] exiting gracefully
[00001000] free env 00001000
No runnable environments in the system!
Welcome to the JOS kernel monitor!
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> QEMU: Terminated
```

### Exercise 14

> Exercise 14. Modify the kernel's trap_dispatch() function so that it calls sched_yield() to ﬁnd and run a different environment whenever a clock interrupt takes place.

处理timer interrupt，`lapic_eoi()`用来acknowledge interrupt

```c
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
		lapic_eoi();
		sched_yield();
		return;
	}
```

### Exercise 15

> Exercise 15. Implement sys_ipc_recv and sys_ipc_try_send in kern/syscall.c. Read the comments on both before implementing them, since they have to work together. When you call envid2env in these routines, you should set the checkperm ﬂag to 0, meaning that any environment is allowed to send IPC messages to any other environment, and the kernel does no special permission checking other than verifying that the target envid is valid.
>
> Then implement the ipc_recv and ipc_send functions in lib/ipc.c.

这里要实现一个进程间通信（IPC）机制，有点类似linux的signal。不仅发送一个32-bit value，还发送一个page mapping。进程调用`ipc_recv`后会阻塞一直等待，调用`ipc_send`后会一直给尝试目标进程发信号，直到目标进程接收。

一个比较坑的地方在于`sys_ipc_recv`这个函数只有出现error才返回，否则不会返回，而是在`sys_ipc_try_send`里被设置为`ENV_RUNNABLE`；但这是一个syscall，必须要返回0才行，所以`sys_ipc_try_send`里要`e->env_tf.tf_regs.reg_eax = 0;`，否则就会panic。

```c
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	int r;
	struct Env *e;
	r = envid2env(envid, &e, 0);
	if (r < 0) return -E_BAD_ENV;
	if (e->env_ipc_recving == 0) return -E_IPC_NOT_RECV;

	uintptr_t va = (uintptr_t) srcva;
	if (va < UTOP) { // send a page mapping
		pte_t *pte;
		struct PageInfo *page = page_lookup(curenv->env_pgdir, srcva, &pte);
		if (va % PGSIZE != 0) return -E_INVAL;
		if (!(perm & (PTE_U | PTE_P)) || (perm & ~PTE_SYSCALL)) return -E_INVAL;
		if (page == NULL) return -E_INVAL;
		if ((perm & PTE_W) && !(*pte & PTE_W)) return -E_INVAL;

		if ((uintptr_t)e->env_ipc_dstva < UTOP) { // receive a page mapping
			r = page_insert(e->env_pgdir, page, e->env_ipc_dstva, perm);
			if (r < 0) return r;
			e->env_ipc_perm = perm;
		}
		else {
			e->env_ipc_perm = 0;
		}
	}
	e->env_ipc_recving = 0;
	e->env_ipc_from = curenv->env_id;
	e->env_ipc_value = value;
	e->env_status = ENV_RUNNABLE;
	e->env_tf.tf_regs.reg_eax = 0; // NOTE: set the return value of sys_ipc_recv!
	return 0;
}

static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	uintptr_t va = (uintptr_t) dstva;
	if ((va < UTOP) && (va % PGSIZE != 0)) return -E_INVAL;
	curenv->env_ipc_recving = 1;
	curenv->env_ipc_dstva = dstva;
	curenv->env_status = ENV_NOT_RUNNABLE;
	sched_yield();
	return 0;
}
```

```c
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
	// LAB 4: Your code here.
	int r;
	if (pg) r = sys_ipc_recv(pg);
	else r = sys_ipc_recv((void*)UTOP);
	if (r < 0) {
		if (from_env_store) *from_env_store = 0;
		if (perm_store) *perm_store = 0;
		return r;
	}
	else {
		if (from_env_store) *from_env_store = thisenv->env_ipc_from;
		if (perm_store) *perm_store = thisenv->env_ipc_perm;
		return thisenv->env_ipc_value;
	}
}

void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
	// LAB 4: Your code here.
	int r;
	while (true) {
		if (pg) r = sys_ipc_try_send(to_env, val, pg, perm);
		else r = sys_ipc_try_send(to_env, val, (void*)UTOP, perm);
		if (r == 0) break;
		else if (r < 0 && r != -E_IPC_NOT_RECV)
			panic("ipc_send error: send failed, %e", r);
		sys_yield();
	}
}
```

### Challenge 6

> Challenge! Implement a shared-memory fork() called sfork(). This version should have the parent and child share all their memory pages (so writes in one environment appear in the other) except for pages in the stack area, which should be treated in the usual copy-on-write manner. Modify user/forktree.c to use sfork() instead of regular fork(). Also, once you have ﬁnished implementing IPC in part C, use your sfork() to run user/pingpongs. You will have to ﬁnd a new way to provide the functionality of the global thisenv pointer.

类似fork，只是把COW的page都复制一份变成writable的（原本writable的不用变），然后parent和child都映射到这上面。user stack拿出来单独处理。

```c
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
```



## This completes the lab.

make grade结果：

```
dumbfork: OK (2.3s) 
Part A score: 5/5

faultread: OK (1.9s) 
faultwrite: OK (2.0s) 
faultdie: OK (1.7s) 
faultregs: OK (2.9s) 
faultalloc: OK (2.9s) 
faultallocbad: OK (3.1s) 
faultnostack: OK (1.7s) 
faultbadhandler: OK (2.6s) 
faultevilhandler: OK (2.9s) 
forktree: OK (2.0s) 
Part B score: 50/50

spin: OK (2.4s) 
stresssched: OK (3.5s) 
sendpage: OK (2.6s) 
    (Old jos.out.sendpage failure log removed)
pingpong: OK (3.3s) 
    (Old jos.out.pingpong failure log removed)
primes: OK (8.2s) 
    (Old jos.out.primes failure log removed)
Part C score: 25/25

Score: 80/80
```





