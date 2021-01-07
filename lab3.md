# Report for lab3

Wenhao Tang, 1800013088

选择做了challenge1

[TOC]

## Part A: User Environments and Exception Handling

### Exercise 1

> Exercise 1. Modify mem_init() in kern/pmap.c to allocate and map the envs array. This array consists of exactly NENV instances of the Env structure allocated much like how you allocated the pages array. Also like the pages array, the memory backing envs should also be mapped user read-only at UENVS (deﬁned in inc/memlayout.h) so user processes can read from this array.

这个练习让我们分配`struct Env *envs `数组，并映射到`UENVS`开始的位置。

这个数组大小为$NENV = 2^{10}$，为每个environment（无论是active还是inactive）保存了一个struct. 

分配和映射过程与`pages`数组类似，代码如下：

```c
	envs = (struct Env *) boot_alloc(NENV * sizeof(struct Env));
	memset(envs, 0, NENV * sizeof(struct Env));

	boot_map_region(
		kern_pgdir,
		UENVS,
		ROUNDUP(NENV * sizeof(struct Env), PGSIZE),
		PADDR(envs),
		PTE_U | PTE_P
	);
```

### Exercise 2

#### `env_init()`

> Initialize all of the Env structures in the envs array and add them to the env_free_list. Also calls env_init_percpu, which conﬁgures the segmentation hardware with separate segments for privilege level 0 (kernel) and privilege level 3 (user).

只要初始化设置`env`数组的每个条目并放入`env_free_list`即可。注意是插入链表头部，所以倒序

```c
void
env_init(void)
{
	// Set up envs array
	// LAB 3: Your code here.
	for (int i = NENV - 1; i >= 0; i--) {
		envs[i].env_id = 0;
		envs[i].env_status = ENV_FREE;
		envs[i].env_link = env_free_list;
		env_free_list = &envs[i]; // insert to head
	}

	// Per-CPU part of the initialization
	env_init_percpu();
}
```

#### `env_setup_vm()`

> Allocate a page directory for a new environment and initialize the kernel portion of the new environment's address space.

```c
	// LAB 3: Your code here.
	e->env_pgdir = page2kva(p);
	memcpy(e->env_pgdir + PDX(UTOP),
				kern_pgdir + PDX(UTOP),
				(NPDENTRIES - PDX(UTOP)) * sizeof(pde_t));
	p->pp_ref++;

	// UVPT maps the env's own page table read-only.
	// Permissions: kernel R, user R
	e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;
```

这里要建立一个environment的page directory. 之前已经分配并清0了一个physical page `p`，将`e->env_pgdir`设置为`p`的kernel visual address（就是物理地址+`KERNBASE`）。然后用`kern_pgdir`的内容作为模板，`UTOP`之上的页目录条目直接复制一份即可（也就是说这些页表都是一样的，因为权限原因user environment无法修改这些，所以没问题）。

还要将`pp_ref++`，这是为了后面的`env_free`。

#### `region_alloc()`

> Allocates and maps physical memory for an environment

```c
static void
region_alloc(struct Env *e, void *va, size_t len)
{
	// LAB 3: Your code here.
	// (But only if you need it for load_icode.)
	//
	// Hint: It is easier to use region_alloc if the caller can pass
	//   'va' and 'len' values that are not page-aligned.
	//   You should round va down, and round (va + len) up.
	//   (Watch out for corner-cases!)
	uint32_t begin = ROUNDDOWN(va, PGSIZE), end = ROUNDUP(va + len, PGSIZE);
	for (uint32_t curva = begin; curva < end; curva += PGSIZE) {
		struct PageInfo* p = page_alloc(0);
		if (!p) 
			panic("[region_alloc] out of memory.");
		int flag = page_insert(e->env_pgdir, p, (void *) curva, PTE_W | PTE_U);
		if (flag == -E_NO_MEM) 
			panic("[region_alloc] page_insert failed, out of memory.");
	}
}
```

以`PGSIZE`为间隔遍历这段virtual address区域，依次`page_alloc`分配物理内存 + `page_insert`建立虚拟地址到物理地址映射即可。

#### `load_icode()`

> You will need to parse an ELF binary image, much like the boot loader already does, and load its contents into the user address space of a new environment.

```c
	// LAB 3: Your code here.
	struct Elf *elfhdr = (struct Elf *) binary;
	if (elfhdr->e_magic != ELF_MAGIC)
		panic("[load_icode] Elf image broken.");

	struct Proghdr *ph, *eph;
	ph = (struct Proghdr *) (binary + elfhdr->e_phoff);
	eph = ph + elfhdr->e_phnum;
	lcr3(PADDR(e->env_pgdir)); // load pa of env_pgdir into cr3
	for (; ph < eph; ph++) if (ph->p_type == ELF_PROG_LOAD) {
		region_alloc(e, (void*)ph->p_va, ph->p_memsz);
		memset((void*)ph->p_va, 0, ph->p_memsz);
		memcpy((void*)ph->p_va, binary + ph->p_offset, ph->p_filesz);
	}
	lcr3(PADDR(kern_pgdir)); // restore cr3
	e->env_tf.tf_eip = elfhdr->e_entry; // set entry point

	// Now map one page for the program's initial stack
	// at virtual address USTACKTOP - PGSIZE.

	// LAB 3: Your code here.
	region_alloc(e, (void*)(USTACKTOP - PGSIZE), PGSIZE);`
```

这个函数将一个ELF文件载入了environment。首先通过ELF header得到program headers（即各个segments），然后依次对于需要映射的segments，使用`region_alloc`给他们分配空间进行映射，然后把elf文件中的内容copy过去，其余清零（如data segment中的`.bss`部分）。

注意因为我们要操作environment的虚拟内存空间，需要将pgdir设置成environment的，使用`lcr3(PADDR(e->env_pgdir));`实现。

还要设置entry point，只要将environment保存的eip设置成entry point地址即可。

#### `env_create()`

> Allocate an environment with env_alloc and call load_icode to load an ELF binary into it.

```c
void
env_create(uint8_t *binary, enum EnvType type)
{
	// LAB 3: Your code here.
	struct Env *e;
	env_alloc(&e, 0);
	load_icode(e, binary);
	e->env_type = type;
}
```

按照要求做即可

#### `env_run()`

> Start a given environment running in user mode.

```c
	// LAB 3: Your code here.
	if (curenv != NULL && curenv->env_status == ENV_RUNNING)
		curenv->env_status = ENV_RUNNABLE;
	curenv = e;
	curenv->env_status = ENV_RUNNING;
	curenv->env_runs++;
	lcr3(PADDR(curenv->env_pgdir));
	env_pop_tf(&curenv->env_tf);
```

按照要求做即可。注意判断一下`curenv`有没有。

使用gdb调试结果如下：

```shell
(gdb) b env_pop_tf
Breakpoint 1 at 0xf0103b5a: file kern/env.c, line 463.
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0xf0103b5a <env_pop_tf>:     endbr32 

Breakpoint 1, env_pop_tf (tf=0xf01d2000) at kern/env.c:463
463     {
(gdb) si
=> 0xf0103b5e <env_pop_tf+4>:   push   %ebp
0xf0103b5e      463     {
(gdb) si
=> 0xf0103b5f <env_pop_tf+5>:   mov    %esp,%ebp
0xf0103b5f in env_pop_tf (tf=0xf0103be9 <env_run+87>) at kern/env.c:463
463     {
(gdb) si
=> 0xf0103b61 <env_pop_tf+7>:   push   %ebx
0xf0103b61      463     {
(gdb) si
=> 0xf0103b62 <env_pop_tf+8>:   sub    $0x8,%esp
0xf0103b62 in env_pop_tf (tf=0xf011afd8) at kern/env.c:463
463     {
(gdb) si
=> 0xf0103b65 <env_pop_tf+11>:  call   0xf0100173 <__x86.get_pc_thunk.bx>
0xf0103b65 in env_pop_tf (tf=0x0) at kern/env.c:463
463     {
(gdb) si
=> 0xf0100173 <__x86.get_pc_thunk.bx>:  mov    (%esp),%ebx
0xf0100173 in __x86.get_pc_thunk.bx ()
(gdb) si
=> 0xf0100176 <__x86.get_pc_thunk.bx+3>:        ret    
0xf0100176 in __x86.get_pc_thunk.bx ()
(gdb) si
=> 0xf0103b6a <env_pop_tf+16>:  add    $0x89996,%ebx
0xf0103b6a in env_pop_tf (tf=0x0) at kern/env.c:463
463     {
(gdb) si
=> 0xf0103b70 <env_pop_tf+22>:  mov    0x8(%ebp),%esp
464             asm volatile(
(gdb) si
=> 0xf0103b73 <env_pop_tf+25>:  popa   
0xf0103b73 in env_pop_tf (tf=0x0) at kern/env.c:464
464             asm volatile(
(gdb) si
=> 0xf0103b74 <env_pop_tf+26>:  pop    %es
0xf0103b74 in env_pop_tf (tf=<error reading variable: Unknown argument list address for `tf'.>)
    at kern/env.c:464
464             asm volatile(
(gdb) si
=> 0xf0103b75 <env_pop_tf+27>:  pop    %ds
0xf0103b75      464             asm volatile(
(gdb) si
=> 0xf0103b76 <env_pop_tf+28>:  add    $0x8,%esp
0xf0103b76      464             asm volatile(
(gdb) si
=> 0xf0103b79 <env_pop_tf+31>:  iret   
0xf0103b79      464             asm volatile(
(gdb) si
=> 0x800020:    cmp    $0xeebfe000,%esp
0x00800020 in ?? ()
```

到这一步时成功运行到`iret`指令，下一条是`lib/entry.S`的第一条指令。然后在`hello.asm`中找到`int $0x30`的地址，设置断点，继续运行：

```shell
(gdb) b *0x800c07
Breakpoint 2 at 0x800c07
(gdb) c
Continuing.
=> 0x800c07:    int    $0x30

Breakpoint 2, 0x00800c07 in ?? ()
(gdb) si
=> 0x800c07:    int    $0x30

Breakpoint 2, 0x00800c07 in ?? ()
```

到达`int $0x30`时仍然正常运行，`si`之后发生triple fault。说明目前的实现是正确的。

### Exercise 3

> **Exercise 3.** Read [Chapter 9, Exceptions and Interrupts](https://pdos.csail.mit.edu/6.828/2018/readings/i386/c09.htm) in the [80386 Programmer's Manual](https://pdos.csail.mit.edu/6.828/2018/readings/i386/toc.htm) (or Chapter 5 of the [IA-32 Developer's Manual](https://pdos.csail.mit.edu/6.828/2018/readings/ia32/IA32-3A.pdf)), if you haven't already.

已读

### Exercise 4

> Edit trapentry.S and trap.c and implement the features described above. The macros TRAPHANDLER and TRAPHANDLER_NOEC in trapentry.S should help you, as well as the T_* deﬁnes in inc/trap.h. You will need to add an entry
>
> point in trapentry.S (using those macros) for each trap deﬁned in inc/trap.h, and you'll have to provide _alltraps which the TRAPHANDLER macros refer to. You will also need to modify trap_init() to initialize the idt to point to each of these entry points deﬁned in trapentry.S; the SETGATE macro will be helpful here.
>
> Your _alltraps should:
>
> 1. push values to make the stack look like a struct Trapframe
>
> 2. load GD_KD into %ds and %es
>
> 3. pushl %esp to pass a pointer to the Trapframe as an argument to trap()
>
> 4. call trap (can trap ever return?)
>
> Consider using the pushal instruction; it ﬁts nicely with the layout of the struct Trapframe.

这个练习让我们初始化IDT（文件`trap.c`中的`trap_init()`）并实现到`0-31`的中断的handler的入口点（文件`trapentry.S`中）。

首先，我们在`trapentry.S`中建立每个handler的入口点，只需要区分每个interrupt/exception是否有error code，可以参考https://wiki.osdev.org/Exceptions。

```assembly
/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TRAPHANDLER_NOEC(divide_handler, T_DIVIDE)
TRAPHANDLER_NOEC(debug_handler, T_DEBUG)
TRAPHANDLER_NOEC(nmi_handler, T_NMI)
TRAPHANDLER_NOEC(brkpt_handler, T_BRKPT)
TRAPHANDLER_NOEC(oflow_handler, T_OFLOW)
TRAPHANDLER_NOEC(bound_handler, T_BOUND)
TRAPHANDLER_NOEC(illop_handler, T_ILLOP)
TRAPHANDLER_NOEC(device_handler, T_DEVICE)
TRAPHANDLER(dblflt_handler, T_DBLFLT) /* 8 error code */
/* TRAPHANDLER_NOEC(coproc_handler, T_COPROC) 9 */
TRAPHANDLER(tss_handler, T_TSS) /* 10 error code */
TRAPHANDLER(segnp_handler, T_SEGNP) /* 11 error code */
TRAPHANDLER(stack_handler, T_STACK) /* 12 error code */
TRAPHANDLER(gpflt_handler, T_GPFLT) /* 13 error code */
TRAPHANDLER(pgflt_handler, T_PGFLT) /* 14 error code */
/*  TRAPHANDLER_NOEC(res_handler, T_RES) ;15 */
TRAPHANDLER_NOEC(fperr_handler, T_FPERR)
TRAPHANDLER(align_handler, T_ALIGN) /* 17 error code */
TRAPHANDLER_NOEC(mchk_handler, T_MCHK)
TRAPHANDLER_NOEC(simderr_handler, T_SIMDERR)
```

然后，我们要实现`trapentry.S`中的`_alltraps`这个函数，这个函数是在`TRAPHANDLER`宏末尾会跳转到的函数。他的功能如下：

1. push values to make the stack look like a struct Trapframe
2. load GD_KD into %ds and %es
3. pushl %esp to pass a pointer to the Trapframe as an argument to trap()
4. call trap (can trap ever return?)

需要注意的是，这部分push一部分是硬件做的一部分是软件做的，硬件做的是：

![img](typora_images/lab3.assets/fig9-5.gif)

观察`TrapFrame`结构，代码中的注释告诉我们从`tf_err`（也就是error code）向下都是硬件做的，并且最下面还有一些只有从user mode跳转到kernel mode才做的：

```c
struct Trapframe {
	struct PushRegs tf_regs;
	uint16_t tf_es;
	uint16_t tf_padding1;
	uint16_t tf_ds;
	uint16_t tf_padding2;
	uint32_t tf_trapno;
	/* below here defined by x86 hardware */
	uint32_t tf_err;
	uintptr_t tf_eip;
	uint16_t tf_cs;
	uint16_t tf_padding3;
	uint32_t tf_eflags;
	/* below here only when crossing rings, such as from user to kernel */
	uintptr_t tf_esp;
	uint16_t tf_ss;
	uint16_t tf_padding4;
} __attribute__((packed));
```

`TRAPHANDLER`宏最后执行了`pushl $(num)`，就是将异常号push进去。通过`TrapFrame`可知接下来应该是`ds, es, PushRegs`。代码如下：

```assembly
/*
 * Lab 3: Your code here for _alltraps
 */
.global _alltraps
.type _alltraps, @function
_alltraps:
	pushl %ds /* 需要倒着push，并且从trapno后的ds开始 */
	pushl %es
	pushal
	movl $(GD_KT), %eax
	mov %ax, %ds
	mov %ax, %es
	pushl %esp
	call trap
```

最后，我们要实现`trap_init`，使用`SETGATE(gate, istrap, sel, off, dpl)`，istrap通过https://wiki.osdev.org/Exceptions来查询每个interrupt是不是trap，sel就是`GD_KT`（内核代码段），off可以使用名字来定位，dpl一般都是0（JOS中内核态就是x86中的privilege level 0），但要注意brkpt这个终端的dpl是3，这个是可以让用户进程主动触发的（Question 3也提到了这个问题）。代码如下：

```c
	// LAB 3: Your code here.
	extern void divide_handler();
	extern void debug_handler();
	extern void nmi_handler();
	extern void brkpt_handler();
	extern void oflow_handler();
	extern void bound_handler();
	extern void illop_handler();
	extern void device_handler();
	extern void dblflt_handler();
	extern void tss_handler();
	extern void segnp_handler();
	extern void stack_handler();
	extern void gpflt_handler();
	extern void pgflt_handler();
	extern void fperr_handler();
	extern void align_handler();
	extern void mchk_handler();
	extern void simderr_handler();

	SETGATE(idt[0], 0, GD_KT, divide_handler, 0);
	SETGATE(idt[1], 0, GD_KT, debug_handler, 0);
	SETGATE(idt[2], 0, GD_KT, nmi_handler, 0);
	SETGATE(idt[3], 1, GD_KT, brkpt_handler, 3);
	SETGATE(idt[4], 1, GD_KT, oflow_handler, 0);
	SETGATE(idt[5], 0, GD_KT, bound_handler, 0);
	SETGATE(idt[6], 0, GD_KT, illop_handler, 0);
	SETGATE(idt[7], 0, GD_KT, device_handler, 0);
	SETGATE(idt[8], 0, GD_KT, dblflt_handler, 0);
	SETGATE(idt[10], 0, GD_KT, tss_handler, 0);
	SETGATE(idt[11], 0, GD_KT, segnp_handler, 0);
	SETGATE(idt[12], 0, GD_KT, stack_handler, 0);
	SETGATE(idt[13], 0, GD_KT, gpflt_handler, 0);
	SETGATE(idt[14], 0, GD_KT, pgflt_handler, 0);
	SETGATE(idt[16], 0, GD_KT, fperr_handler, 0);
	SETGATE(idt[17], 0, GD_KT, align_handler, 0);
	SETGATE(idt[18], 0, GD_KT, mchk_handler, 0);
	SETGATE(idt[19], 0, GD_KT, simderr_handler, 0);
```

### Challenge 1

> Challenge! You probably have a lot of very similar code right now, between the lists of TRAPHANDLER in trapentry.S and their installations in trap.c. Clean this up. Change the macros in trapentry.S to automatically generate a table for trap.c to use. Note that you can switch between laying down code and data in the assembler by using the directives .text and .data.

修改`TRAPHANDLER`如下：

```assembly
#define TRAPHANDLER(name, num)						\
	.text; \
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps; \
	.data; \
	.long name; \

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.text; \
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps; \
	.data; \
	.long name; \
```

在handlers的入口点开始位置添加一个.data段的符号声明：

```assembly
.data
.global handlers
handlers:
```

这样我们就在`.data`段有了一个数组`handlers`，数组的每个条目是个32位的地址，第i个条目指向第i个handler的代码起始位置。这样`trap_init`就可以简化了：

```c
	extern uint32_t handlers[];
	for (int i = 0; i < 20; i++) {
		if (i == T_BRKPT) SETGATE(idt[i], 1, GD_KT, handlers[i], 3)
		else SETGATE(idt[i], 1, GD_KT, handlers[i], 0)
	}
```

### Questions

> 1. What is the purpose of having an individual handler function for each exception/interrupt? (i.e., if all exceptions/interrupts were delivered to the same handler, what feature that exists in the current implementation could not be provided?)
> 2.  Did you have to do anything to make the user/softint program behave correctly? The grade script expects it to produce a general protection fault (trap 13), but softint's code says int `$14`. Why should this produce interrupt vector 13? What happens if the kernel actually allows softint's int `$14` instruction to invoke the kernel's page fault handler (which is interrupt vector 14)?

1. 不同handlers可以有不同的error code设置与不同的privilege level
2. 用户程序没有权限直接调用privilege level为0的page fault handler，所以会触发general protection error，也就是13中断. 如果允许的话，一方面用户进程就能在一定程度上影响内存管理（页面调度）过程，这好吗，这不好；另一方面用户进程可以来骗操作系统，把一些没有page fault的页又调度进来一次。

---

### 总结一下中断/异常处理的过程：

中断/异常发生时，CPL从user切换到kernel，同时转到使用kernel stack（一个叫task state segment(TSS)的结构保存了kernel stack的segment selector和address，应该每个process都有自己的kernel stack，但这里好像一个处理器是一个kernel stack）。处理器（硬件）在这个stack里push了SS, ESP, EFLAGS, CS, EIP, and an optional error code. 然后从interrupt descriptor table中找到interrupt descriptor，设置CS和EIP开始执行`trapEntry.S`中`TRAPHANDLER`的汇编代码，软件又push了一些东西（此时ss和esp已经设置成kernel stack了），主要是其他registers见TrapFrame结构。然后跳到`trap()`，又跳到`trap_dispatch()`，开始真正执行各个handler。

## Part B: Page Faults, Breakpoints Exceptions, and System Calls

### Exercise 5

> Exercise 5. Modify trap_dispatch() to dispatch page fault exceptions to page_fault_handler().

检查trap number然后dispatch即可。

```c
	if (tf->tf_trapno == T_PGFLT) {
		page_fault_handler(tf);
		return;
	}
```

### Exercise 6

> Exercise 6. Modify trap_dispatch() to make breakpoint exceptions invoke the kernel monitor.

同上。

```c
	if (tf->tf_trapno == T_BRKPT) {
		monitor(tf);
		return;
	}
```

### Questions

> 3. The break point test case will either generate a break point exception or a general protection fault depending on how you initialized the break point entry in the IDT (i.e., your call to SETGATE from trap_init). Why? How do you need to set it up in order to get the breakpoint exception to work as speciﬁed above and what incorrect setup would cause it to trigger a general protection fault?
>
> 4. What do you think is the point of these mechanisms, particularly in light of what the user/softint test program does?

3. dpl=0时触发general protection fault，dpl=3时触发break point exception。需要将dpl设置成3用户进程才有权限主动触发。
4. 因为exception是在kernel mode执行的，将大部分exception的dpl设置为0防止用户进程主动触发一些exception，更好地实现保护；同时将一部分exception的depl设置为3可以让用户进程方便地实现一些必要的指令，让用户进程通过exception handler的方式受限的执行这些功能。

### Exercise 7

> Exercise 7. Add a handler in the kernel for interrupt vector T_SYSCALL. You will have to edit kern/trapentry.S and kern/trap.c's trap_init(). You also need to change trap_dispatch() to handle the system call interrupt by calling
>
> syscall() (deﬁned in kern/syscall.c) with the appropriate arguments, and then arranging for the return value to be passed back to the user process in %eax. Finally, you need to implement syscall() in kern/syscall.c. Make sure syscall()
>
> returns -E_INVAL if the system call number is invalid. You should read and understand lib/syscall.c (especially the inline assembly routine) in order to conﬁrm your understanding of the system call interface. Handle all the system calls listed in inc/syscall.h by invoking the corresponding kernel function for each call.

首先，在`trapentry.S`和`trap_init`中添加syscall有关的内容:

```assembly
TRAPHANDLER_NOEC(syscall_handler, T_SYSCALL)
```

```c
extern void syscall_handler();
SETGATE(idt[T_SYSCALL], 1, GD_KT, syscall_handler, 3);
```

然后，实现`kern/syscall.c`，只要对不同syscallno调用不同函数即可

```c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.

	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((char *)a1, a2);
		case SYS_cgetc:
			return sys_cgetc();
		case SYS_getenvid:
			return sys_getenvid();
		case SYS_env_destroy:
			sys_env_destroy(a1);
		default:
			return -E_INVAL;
	}
}
```

还要在`trap_dispatch`中加入对`T_SYSCALL`的处理，注意传递参数的顺序：`%eax, %edx, %ecx, %ebx, %edi, %esi`

```c
	else if (tf->tf_trapno == T_SYSCALL) {
		struct PushRegs *regs = &tf->tf_regs;
		int32_t ret = syscall(regs->reg_eax, regs->reg_edx, regs->reg_ecx, regs->reg_ebx, regs->reg_edi, regs->reg_esi);
		regs->reg_eax = ret;
		return;
	}
```

### Exercise 8

> Modify libmain() to initialize the global pointer thisenv to point at this environment's struct Env in the envs[] array.

```c
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	thisenv = &envs[ENVX(sys_getenvid())];
```

用户进程从`lib/entry.S`的`_start`开始执行，结尾调用了`lib/libmain.c`中的`libmain()`函数，这个函数中需要设置`thisenv`指向当前environment的struct Env，代码如上所示。`libmain()`的结尾调用了`umain`，就是用户程序的主函数。这个过程和x86中用户进程开始执行的过程很像。

### Exercise 9

> Change kern/trap.c to panic if a page fault happens in kernel mode.
>
> Hint: to determine whether a fault happened in user mode or in kernel mode, check the low bits of the tf_cs.
>

在`env.c`中有如下描述："The low 2 bits of each segment register contains the Requestor Privilege Level (RPL); 3 means user mode." 所以我们只要检查`low_bits`的低2位，全是1说明是user mode的page fault。代码如下：

```c
	if ((tf->tf_cs & 3) != 3) 
    panic("[page_fault_handler] kernel mode page fault.")
```

> Read user_mem_assert in kern/pmap.c and implement user_mem_check in that same ﬁle.
>
> Change kern/syscall.c to sanity check arguments to system calls.

接下来实现`user_mem_check`的内存检查功能。舍入算出开始和结束，然后每个page检查即可。需要注意的是第一个page是从`va`开始的（而不是这个page的开始地址），需要特判一下。代码如下：

```c
int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
	// LAB 3: Your code here.
	perm = perm | PTE_P;
	uint32_t begin = ROUNDDOWN((uint32_t)va, PGSIZE), end = ROUNDUP((uint32_t)(va + len), PGSIZE);
	bool first = 1;
	for (; begin < end; begin += PGSIZE) {
		if (begin >= ULIM) {
			if (first) user_mem_check_addr = (uint32_t) va;
			else user_mem_check_addr = begin;
			return -E_FAULT;
		}
		pte_t *pte = pgdir_walk(env->env_pgdir, (void *) begin, 0);
		if (!pte || ((*pte & perm) != perm)) {
			if (first) user_mem_check_addr = (uint32_t) va;
			else user_mem_check_addr = begin;
			return -E_FAULT;
		}
		first = 0;
	}
	
	return 0;
}
```

`kern/syscall.c`中的部分如下：

```c
	user_mem_assert(curenv, s, len, PTE_U);
```

> Finally, change debuginfo_eip in kern/kdebug.c to call user_mem_check on usd, stabs, and stabstr. 

只要检查即可，权限是`PTE_U`：

```c
		// Make sure this memory is valid.
		// Return -1 if it is not.  Hint: Call user_mem_check.
		// LAB 3: Your code here.
		if (user_mem_check(curenv, usd, sizeof(struct UserStabData), PTE_U) < 0)
			return -1;

		// Make sure the STABS and string table memory is valid.
		// LAB 3: Your code here.
		if (user_mem_check(curenv, stabs, (size_t)stab_end - (size_t)stabs, PTE_U) < 0)
			return -1;
		if (user_mem_check(curenv, stabstr, (size_t)stabstr_end - (size_t)stabstr, PTE_U) < 0)
			return -1;
```

> Finally, change debuginfo_eip in kern/kdebug.c to call user_mem_check on usd, stabs, and stabstr. If you now run user/breakpoint, you should be able to run backtrace from the kernel monitor and see the backtrace traverse into lib/libmain.c before the kernel panics with a page fault. What causes this page fault? You don't need to ﬁx it, but you should understand why it happens.

结果如下所示：

```
K> backtrace
Stack backtrace:
  ebp efffff00  eip f0100ddc  args 00000001 efffff28 f01d3000 f018e568 f0106b89
         kern/monitor.c:224: monitor+368
  ebp efffff80  eip f01044cf  args f01d3000 efffffbc f01517b4 00000082 f011bfd8
         kern/trap.c:161: trap+316
  ebp efffffb0  eip f011d396  args efffffbc 00000000 00000000 eebfdff0 efffffdc
         <unknown>:0: <unknown>+0
  ebp eebfdff0  eip 00800031  args 00000000 00000000Incoming TRAP frame at 0xeffffe64
kernel panic at kern/trap.c:231: [page_fault_handler] kernel mode page fault.
```

原因是`0xeffffe64`（kernel stack）发生了page fault？

### Exercise 10

> Exercise 10. Boot your kernel, running user/evilhello. The environment should be destroyed, and the kernel should not panic.

结果如下所示：

```shell
[00000000] new env 00001000
Incoming TRAP frame at 0xefffffbc
Incoming TRAP frame at 0xefffffbc
[00001000] user_mem_check assertion failure for va f010000c
[00001000] free env 00001000
Destroyed the only environment - nothing more to do!
```

## This completes the lab.

`make grade`结果：

```
divzero: OK (2.1s) 
softint: OK (0.9s) 
badsegment: OK (1.2s) 
Part A score: 30/30

faultread: OK (1.2s) 
faultreadkernel: OK (1.1s) 
faultwrite: OK (2.0s) 
faultwritekernel: OK (1.9s) 
breakpoint: OK (2.7s) 
testbss: OK (2.4s) 
hello: OK (1.2s) 
buggyhello: OK (2.1s) 
buggyhello2: OK (2.1s) 
evilhello: OK (1.8s) 
Part B score: 50/50

Score: 80/80
```

