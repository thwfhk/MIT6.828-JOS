# Report for lab2

Wenhao Tang, 1800013088

选择做了challenge1

[TOC]

## Part 1: Physical Page Management

### Exercise 1

> **Exercise 1.** In the file `kern/pmap.c`, you must implement code for the following functions (probably in the order given).
>
> ```
> boot_alloc()
> mem_init()   (only up to the call to `check_page_free_list(1)`)
> page_init()
> page_alloc()
> page_free()
> ```
>
> `check_page_free_list()` and `check_page_alloc()` test your physical page allocator. You should boot JOS and see whether `check_page_alloc()` reports success. Fix your code so that it passes. You may find it helpful to add your own `assert()`s to verify that your assumptions are correct.

#### 1.1 `boot_alloc()`

```c
	// Allocate a chunk large enough to hold 'n' bytes, then update
	// nextfree.  Make sure nextfree is kept aligned
	// to a multiple of PGSIZE.
	//
	// LAB 2: Your code here.
	result = nextfree;
	nextfree += ROUNDUP(n, PGSIZE);
	if ((size_t)nextfree > KERNBASE + npages * PGSIZE) 
		panic("boot_alloc: Physical memory ran out.\n");

	return result;
```

这里我们要实现的功能是分配`n`字节物理内存并保持PGSIZE-aligned。我们可用的物理内存是从nextfree开始的，nextfree的初值是`end = 0xf01156a0`。

注意kernel被link在`KERNBASE=0xf0000000 - 0xffffffff`，并且在`entry.S`中开启了protection mode，所以我们的程序中所有地址都是虚拟地址。由于在`entry.S`中我们建立了一个临时的`[0,0x400000)`到`[KERNBASE, KERNBASE+0x400000)`的虚拟内存映射，所以当前使用虚拟地址是合法的。

nextfree本来就是PGSIZE-aligned，只要再让n PGSIZE-aligned然后加上即可。

需要判断**内存用完**的情况，由于物理内存（包括base memory和extended memory）映射到kernel virtual memory后是从KERNBASE开始的npages个pages，所以只要判断nextfree增加后是否超过`KERNBASE + npages * PGSIZE`即可。

#### 1.2 `mem_init()`

```c
	//////////////////////////////////////////////////////////////////////
	// Allocate an array of npages 'struct PageInfo's and store it in 'pages'.
	// The kernel uses this array to keep track of physical pages: for
	// each physical page, there is a corresponding struct PageInfo in this
	// array.  'npages' is the number of physical pages in memory.  Use memset
	// to initialize all fields of each struct PageInfo to 0.
	// Your code goes here:
	pages = (struct PageInfo *) boot_alloc(npages * sizeof(struct PageInfo));
	memset(pages, 0, npages * sizeof(struct PageInfo));
```

`mem_init`函数是建立二级页表的主函数。他首先给page directory分配了物理内存`kern_pgdir = (pde_t *) boot_alloc(PGSIZE)`，接下来让我们补充给`pages`数组里`PageInfo`结构分配的物理内存的代码。这个数组里给每个physical page保存了一个`PageInfo`结构，一共有`npages`个physical pages。使用`boot_alloc`分配并用`memset`清空即可。

#### 1.3 `page_init()`

```c
void
page_init(void)
{
	size_t i;
	// pp_ref不需要设置，只要不加入page_free_list就行
	// pages[0].pp_ref = 1; // (1)
	for (i = 1; i < npages_basemem; i++) { // (2)
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
	size_t npages_hole = (EXTPHYSMEM - IOPHYSMEM) / PGSIZE;
	for (i = npages_basemem; i < npages_basemem + npages_hole; i++) { // (3)
		// pages[i].pp_ref = 1;
		pages[i].pp_link = NULL;
	}
	size_t cur_addr = (size_t) boot_alloc(0);
	size_t npages_cur = (cur_addr - KERNBASE) / PGSIZE;
	for (i = npages_basemem + npages_hole; i < npages_cur; i++) { // (4) in use
		// pages[i].pp_ref = 1;
		pages[i].pp_link = NULL;
	}
	for (i = npages_cur; i < npages; i++) { // (4) free
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
}
```

这个函数是将physical pages中尚未使用的那些加到`page_free_list`里。源代码的注释给出了4条提示告诉我们哪些没有使用，代码中有标注：

1. 第一个physical page被使用了 ==这个到底是做什么用的？==
2. base memory里剩下的都没有被使用（base memory一直到`0xA0000`）
3.  d从base memory结束`0xA0000`开始有一段IO hole `[IOPHYSMEM, EXTPHYSMEM)`算作被使用的
4. 接下来是kernel被载入的地方，从`0x100000`开始，一直到`end`；然后是我们前面用`boot_alloc`分配的，也是被使用的。这部分一直到`boot_alloc(0)`所返回的地址（也就是当前`nextfree`）
5. 再后面的extended memory就是可以使用的了

#### 1.4 `page_alloc()`

```c
struct PageInfo *
page_alloc(int alloc_flags)
{
	// Fill this function in
	if (!page_free_list)
		return NULL;
	struct PageInfo *cur_page = page_free_list;
	page_free_list = cur_page -> pp_link;
	cur_page -> pp_link = NULL;
	if (alloc_flags & ALLOC_ZERO) 
		memset(page2kva(cur_page), 0, PGSIZE);
	return cur_page;
}
```

这个函数是从`page_free_list`中分配一个空闲page，就是正常的链表操作。按照要求`pp_ref`不是`page_alloc`和`page_free`里进行操作的。有个清零条件，可以使用`page2kva`从`PageInfo*`得到kernel virtual address。

#### 1.5 `page_free()`

```c
void
page_free(struct PageInfo *pp)
{
	// Fill this function in
	// Hint: You may want to panic if pp->pp_ref is nonzero or
	// pp->pp_link is not NULL.
	if (pp->pp_ref)
		panic("page_free: pp->pp_ref is nonzero\n");
	if (pp->pp_link)
		panic("page_free: pp->pp_link is not NULL\n");
	pp->pp_link = page_free_list;
	page_free_list = pp;
}
```

这里将一个物理页释放，将其`PageInfo*`放到`page_free_list`中。就是正常的链表操作。

## Part 2: Virtual Memory

### Exercise 2

> **Exercise 2.** Look at chapters 5 and 6 of the [Intel 80386 Reference Manual](https://pdos.csail.mit.edu/6.828/2018/readings/i386/toc.htm), if you haven't done so already. Read the sections about page translation and page-based protection closely (**5.2 and 6.4**). We recommend that you also skim the sections about segmentation; while JOS uses the paging hardware for virtual memory and protection, segment translation and segment-based protection cannot be disabled on the x86, so you will need a basic understanding of it.

已读。

### Exercise 3

> **Exercise 3.** While GDB can only access QEMU's memory by virtual address, it's often useful to be able to inspect physical memory while setting up virtual memory. Review the QEMU [monitor commands](https://pdos.csail.mit.edu/6.828/2018/labguide.html#qemu) from the lab tools guide, especially the `xp` command, which lets you inspect physical memory. To access the QEMU monitor, press Ctrl-a c in the terminal (the same binding returns to the serial console).
>
> Use the xp command in the QEMU monitor and the x command in GDB to inspect memory at corresponding physical and virtual addresses and make sure you see the same data.
>
> Our patched version of QEMU provides an info pg command that may also prove useful: it shows a compact but detailed representation of the current page tables, including all mapped memory ranges, permissions, and flags. Stock QEMU also provides an info mem command that shows an overview of which ranges of virtual addresses are mapped and with what permissions.

使用`xp`与`x`检查对应位置的物理和虚拟内存地址的结果如下：

```assembly
(qemu) xp /10x 0x100000
0000000000100000: 0x1badb002 0x00000000 0xe4524ffe 0x7205c766
0000000000100010: 0x34000004 0x4000b812 0x220f0011 0xc0200fd8
0000000000100020: 0x0100010d 0xc0220f80

(gdb) x /10x 0xf0100000
0xf0100000 <_start-268435468>:	0x1badb002	0x00000000	0xe4524ffe	0x7205c766
0xf0100010 <entry+4>:	0x34000004	0x4000b812	0x220f0011	0xc0200fd8
0xf0100020 <entry+20>:	0x0100010d	0xc0220f80
```

发现确实相同。

`info pg`在完成exercise5后的运行结果如下：

```assembly
K> QEMU 2.3.0 monitor - type 'help' for more information
(qemu) info pg
VPN range     Entry         Flags        Physical page
[ef000-ef3ff]  PDE[3bc]     -------UWP
  [ef000-ef03f]  PTE[000-03f] -------U-P 0011c-0015b
[ef400-ef7ff]  PDE[3bd]     -------U-P
  [ef7bc-ef7bc]  PTE[3bc]     -------UWP 003fd
  [ef7bd-ef7bd]  PTE[3bd]     -------U-P 0011b
  [ef7bf-ef7bf]  PTE[3bf]     -------UWP 003fe
  [ef7c0-ef7df]  PTE[3c0-3df] ----A--UWP 003ff 003fc 003fb 003fa 003f9 003f8 ..
  [ef7e0-ef7ff]  PTE[3e0-3ff] -------UWP 003dd 003dc 003db 003da 003d9 003d8 ..
[efc00-effff]  PDE[3bf]     -------UWP
  [efff8-effff]  PTE[3f8-3ff] --------WP 0010f-00116
[f0000-f03ff]  PDE[3c0]     ----A--UWP
  [f0000-f0000]  PTE[000]     --------WP 00000
  [f0001-f009f]  PTE[001-09f] ---DA---WP 00001-0009f
  [f00a0-f00b7]  PTE[0a0-0b7] --------WP 000a0-000b7
  [f00b8-f00b8]  PTE[0b8]     ---DA---WP 000b8
  [f00b9-f00ff]  PTE[0b9-0ff] --------WP 000b9-000ff
  [f0100-f0105]  PTE[100-105] ----A---WP 00100-00105
  [f0106-f0115]  PTE[106-115] --------WP 00106-00115
  [f0116-f0116]  PTE[116]     ---DA---WP 00116
  [f0117-f0117]  PTE[117]     --------WP 00117
  [f0118-f0118]  PTE[118]     ---DA---WP 00118
  [f0119-f0119]  PTE[119]     --------WP 00119
  [f011a-f011b]  PTE[11a-11b] ---DA---WP 0011a-0011b
  [f011c-f011c]  PTE[11c]     ----A---WP 0011c
  [f011d-f011d]  PTE[11d]     ---DA---WP 0011d
  [f011e-f015b]  PTE[11e-15b] ----A---WP 0011e-0015b
  [f015c-f03bd]  PTE[15c-3bd] ---DA---WP 0015c-003bd
  [f03be-f03ff]  PTE[3be-3ff] --------WP 003be-003ff
[f0400-f7fff]  PDE[3c1-3df] ----A--UWP
  [f0400-f7fff]  PTE[000-3ff] ---DA---WP 00400-07fff
[f8000-fffff]  PDE[3e0-3ff] -------UWP
  [f8000-fffff]  PTE[000-3ff] --------WP 08000-0ffff
```

* VPN range是虚拟地址的VPN范围，变成虚拟地址的话在16进制表示的后面加三个0。

* Entry里PTE的话表示PTE编号的范围，共1024个，16进制是`0x000 - 0x3ff`；PDE的话说明前面的虚拟地址范围恰好被一个或几个PT管理，后面跟的编号就是这几个PT的PDE编号。
* Flags就是PTE中的后12位。
* Physical page是这段虚拟内存所映射到的物理内存

### Question

> Assuming that the following JOS kernel code is correct, what type should variable `x` have, `uintptr_t` or `physaddr_t`?
>
> ```
> 	mystery_t x;
> 	char* value = return_a_pointer();
> 	*value = 10;
> 	x = (mystery_t) value;
> ```

The type of `x` should be `uintptr_t`. Because `value` is a pointer in C, which is a virtual addresses.

### Exercise 4

> **Exercise 4.** In the file `kern/pmap.c`, you must implement code for the following functions.
>
> ```
>         pgdir_walk()
>         boot_map_region()
>         page_lookup()
>         page_remove()
>         page_insert()
> ```
>
> `check_page()`, called from `mem_init()`, tests your page table management routines. You should make sure it reports success before proceeding.

这个exercise主要是实现一些操作虚拟内存映射的函数。

#### 4.1`pgdir_walk()`

```c
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
	// Fill this function in
	pde_t pde = pgdir[PDX(va)];
	if (pde & PTE_P) { // the page table page exists
		// notice that we need virtual address
		physaddr_t* pgtable = KADDR(PTE_ADDR(pde)); 
		pte_t* pte_addr = pgtable + PTX(va);
		return pte_addr;
	}
	else { // the page table page doesn't exist
		if (create == false) return NULL;
		struct PageInfo* new_page = page_alloc(ALLOC_ZERO);
		if (!new_page) return NULL;
		new_page->pp_ref ++;
		// change the pde to have the allocated page table address
		pgdir[PDX(va)] = page2pa(new_page) | PTE_U | PTE_W | PTE_P;
		physaddr_t* pgtable = KADDR(page2pa(new_page));
		pte_t* pte_addr = pgtable + PTX(va);
		return pte_addr;
	}
}
```

`pgdir_walk`返回一个给定virtual address对应的page table entry。

* `create = false`时如果***page table不在物理内存中***（即`!(pde & PTE_P)`）就返回`NULL`。

* `create = true`时如果***page table不在物理内存中***就给page table分配一个physical page，如果物理内存不够用了就返回`NULL`。 ==这里没有管页面调度。==

#### 4.2 `boot_map_region()`

```c
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
	// Fill this function in
	for (int i = 0; i < size / PGSIZE; i++) {
		pte_t* pte_addr = pgdir_walk(pgdir, (void*)va, 1);
		if (!pte_addr) panic("boot_map_region: physical memory ran out");
		*pte_addr = pa | PTE_P | perm;
		va += PGSIZE;
		pa += PGSIZE;
	}
}
```

这个函数将`[va, va+size)`虚拟内存映射到`[pa, pa+size)`物理内存，依次设置该虚拟内存范围内的每个page，更新pte中的物理地址部分和权限位。

这个函数只用于**UTOP**之上的内存映射，所以不需要处理`pp_ref`。

#### 4.3 `page_lookup()`

```c
struct PageInfo *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
{
	// Fill this function in
	pte_t* pte_addr = pgdir_walk(pgdir, va, 0);
	if (!pte_addr || !(*pte_addr & PTE_P)) return NULL;
	if (pte_store) *pte_store = pte_addr;
	physaddr_t pa = PTE_ADDR(*pte_addr);
	struct PageInfo* page = pa2page(pa);
	return page;
}
```

这个函数取出一个virtual address所对应的physical page的`PagaInfo`结构，并且可选的将它对应的page table entry存到`pte_store`中。

当该virtual address对应的***pte不在物理内存中***或者***pte不存在（说明page table不在物理内存中）***就返回`NULL`。

#### 4.4 `page_remove()`

```c
void
page_remove(pde_t *pgdir, void *va)
{
	// Fill this function in
	pte_t *pte_ptr;
	struct PageInfo* page = page_lookup(pgdir, va, &pte_ptr);
	if (page) { // 此时说明pte存在且P=1
		page_decref(page);
		*pte_ptr = 0;
		tlb_invalidate(pgdir, va);
	}
}
```

这个函数将一个virtual address对应的physical page释放。`page_decref`函数里会处理`pp_ref--`以及在为0时将physical page加到`page_free_list`

#### 4.5 `page_insert`

```c
int
page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
{
	// Fill this function in
	pte_t* pte_addr = pgdir_walk(pgdir, va, 1);
	if (pte_addr) {
		pp->pp_ref ++;
		if (*pte_addr & PTE_P)
			page_remove(pgdir, va);
		*pte_addr = page2pa(pp) | PTE_P | perm;
		// pgdir[PDX(va)] |= perm; // ???
		return 0;
	}
	else return -E_NO_MEM;
}
```

这个函数将`va`映射到physical page `pp`的物理地址。如果`va`已经映射到其他physical page了，需要先`page_remove`。

需要考虑一个corner case：`va`之前映射的physical page和`pp`是同一个，此时如果先`page_remove`可能会导致这个physical page被释放。所以我们先`pp_ref++`再`page_remove`。



## Part 3: Kernel Address Space

### Exercise 5

> **Exercise 5.** Fill in the missing code in `mem_init()` after the call to `check_page()`.
>
> Your code should now pass the `check_kern_pgdir()` and `check_page_installed_pgdir()` checks.

这个exercise让我们建立`UTOP`之上的虚拟内存映射。这部分的虚拟内存结构如下所示：

```
 *    4 Gig -------->  +------------------------------+
 *                     |                              | RW/--
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     :              .               :
 *                     :              .               :
 *                     :              .               :
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| RW/--
 *                     |                              | RW/--
 *                     |   Remapped Physical Memory   | RW/--
 *                     |                              | RW/--
 *    KERNBASE, ---->  +------------------------------+ 0xf0000000      --+
 *    KSTACKTOP        |     CPU0's Kernel Stack      | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     |     CPU1's Kernel Stack      | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                 PTSIZE
 *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     :              .               :                   |
 *                     :              .               :                   |
 *    MMIOLIM ------>  +------------------------------+ 0xefc00000      --+
 *                     |       Memory-mapped I/O      | RW/--  PTSIZE
 * ULIM, MMIOBASE -->  +------------------------------+ 0xef800000
 *                     |  Cur. Page Table (User R-)   | R-/R-  PTSIZE
 *    UVPT      ---->  +------------------------------+ 0xef400000
 *                     |          RO PAGES            | R-/R-  PTSIZE
 *    UPAGES    ---->  +------------------------------+ 0xef000000
 *                     |           RO ENVS            | R-/R-  PTSIZE
 * UTOP,UENVS ------>  +------------------------------+ 0xeec00000
```

```c
	//////////////////////////////////////////////////////////////////////
	// Map 'pages' read-only by the user at linear address UPAGES
	// Permissions:
	//    - the new image at UPAGES -- kernel R, user R
	//      (ie. perm = PTE_U | PTE_P)
	//    - pages itself -- kernel RW, user NONE
	// Your code goes here:
	boot_map_region(
		kern_pgdir, 
		UPAGES, 
		ROUNDUP(npages * sizeof(struct PageInfo), PGSIZE), 
		PADDR(pages), 
		PTE_U | PTE_P);
```

这里是`UPAGES`开始的一段虚拟内存映射到`pages`数组所在的物理内存，让user获得读权限。

```c
	//////////////////////////////////////////////////////////////////////
	// Use the physical memory that 'bootstack' refers to as the kernel
	// stack.  The kernel stack grows down from virtual address KSTACKTOP.
	// We consider the entire range from [KSTACKTOP-PTSIZE, KSTACKTOP)
	// to be the kernel stack, but break this into two pieces:
	//     * [KSTACKTOP-KSTKSIZE, KSTACKTOP) -- backed by physical memory
	//     * [KSTACKTOP-PTSIZE, KSTACKTOP-KSTKSIZE) -- not backed; so if
	//       the kernel overflows its stack, it will fault rather than
	//       overwrite memory.  Known as a "guard page".
	//     Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(
		kern_pgdir,
		KSTACKTOP - KSTKSIZE,
		KSTKSIZE,
		PADDR(bootstack),
		PTE_W | PTE_P);
```

这里是将kernel stack映射到`bootstack`开始的物理内存。

```c
  //////////////////////////////////////////////////////////////////////
	// Map all of physical memory at KERNBASE.
	// Ie.  the VA range [KERNBASE, 2^32) should map to
	//      the PA range [0, 2^32 - KERNBASE)
	// We might not have 2^32 - KERNBASE bytes of physical memory, but
	// we just set up the mapping anyway.
	// Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(
		kern_pgdir,
		KERNBASE,
		-KERNBASE,
		0,
		PTE_W | PTE_P);
```

这里是将kernel的虚拟内存`[KERNBASE, 2^32)`映射到kernel的物理内存`[0, 2^32 - KERNBASE)`。

### Question

> 2. What entries (rows) in the page directory have been filled in at this point? What addresses do they map and where do they point? In other words, fill out this table as much as possible:

| Entry | Base Virtual Address           | Points to (logically):                   |
| ----- | ------------------------------ | :--------------------------------------- |
| 1023  | 0xffffffff                     | Page table for top 4MB of phys memory    |
| ...   | ...                            | 依次填充所有phys memory                  |
| 0x3c0 | 0xf0000000(KERNBASE)           | Page table for bottom 4MB of phys memory |
| 0x3bf | 0xefc00000(KSTACKTOP - PTSIZE) | `bootstack`                              |
| 0x3bd | 0xef400000(UVPT)               | kernel page directory                    |
| 0x3bc | 0xef000000(UPAGES)             | the `pages` array                        |

> 3. We have placed the kernel and user environment in the same address space. Why will user programs not be able to read or write the kernel's memory? What specific mechanisms protect the kernel memory?

在page directory entry和page table entry的低12位中保存了一些权限信息，只有`U/S=1`时这个entry所映射到的区域才是user programs可读的，在此基础上只有`R/W=1`时才是user program可写的。在page translation的过程中MMU硬件会检查这两位，从而保护kernel memory。

> 4. What is the maximum amount of physical memory that this operating system can support? Why?

256MB。因为kernel需要有全部物理地址的“直接”访问能力，而虚拟地址映射将物理地址`[0x00000000, 0x0fffffff)`映射到虚拟地址`[0xf0000000, 0xffffffff)`，这一部分只有256MB。

> 5. How much space overhead is there for managing memory, if we actually had the maximum amount of physical memory? How is this overhead broken down?

page directory, 4kb

page tables, 4*1024 = 4mb

pages数组, 共256*256个 `PageInfo`，一个8b，共512 kb

(不太确定QwQ)

> 6. Revisit the page table setup in `kern/entry.S` and `kern/entrypgdir.c`. Immediately after we turn on paging, EIP is still a low number (a little over 1MB). At what point do we transition to running at an EIP above KERNBASE? What makes it possible for us to continue executing at a low EIP between when we enable paging and when we begin running at an EIP above KERNBASE? Why is this transition necessary?

At what point do we transition to running at an EIP above KERNBASE? 以下两行代码将EIP转移到KERNBASE之上。

```c
	mov	$relocated, %eax
	jmp	*%eax
```

What makes it possible for us to continue executing at a low EIP between when we enable paging and when we begin running at an EIP above KERNBASE? 同时将虚拟地址`[0, 4MB)`也映射到了物理地址`[0, 4MB)`.

Why is this transition necessary? 因为我们之后要建立`[KERNBASE, KERNBASE+256MB)`到`[0, 256MB)`的虚拟地址映射，让kernel使用高虚拟地址，低虚拟地址让user program使用。

## Challenge 1

> *Challenge!* Extend the JOS kernel monitor with commands to:
>
> - Display in a useful and easy-to-read format all of the physical page mappings (or lack thereof) that apply to a particular range of virtual/linear addresses in the currently active address space. For example, you might enter `'showmappings 0x3000 0x5000'` to display the physical page mappings and corresponding permission bits that apply to the pages at virtual addresses 0x3000, 0x4000, and 0x5000.
> - Explicitly set, clear, or change the permissions of any mapping in the current address space.
> - Dump the contents of a range of memory given either a virtual or physical address range. Be sure the dump code behaves correctly when the range extends across page boundaries!
> - Do anything else that you think might be useful later for debugging the kernel. (There's a good chance it will be!)

### showmappings

`showmappings va_begin va_end`指令用来展示`[va_begin, va_end]`这一段虚拟内存所对应的**虚拟页**所映射到的物理地址开始位置和权限。用`pgwalk_dir`取得pte然后打印即可。

代码实现如下：

```c
int 
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
		cprintf("showmappings error: the number of arguments should be 2.\n");
		cprintf("Usage: showmappings va_begin va_end\n");
		return 0;
	}
	uint32_t begin = strtol(argv[1], NULL, 0), end = strtol(argv[2], NULL, 0);
	for (; begin <= end; begin += PGSIZE) {
		pte_t* pte = pgdir_walk(kern_pgdir, (void *) begin, 0);
		if (!pte) cprintf("Virtual address %x doesn't exist.\n");
		else {
			cprintf("virtual page address:%x\tu/s=%d\tr/w=%d\n", 
							begin & (~0xFFF),
							(bool)(*pte & PTE_U),
							(bool)(*pte & PTE_W));
		}
	}
	return 0;
}
```

示例如下：

```
K> showmappings 0xf0100000 0xf0103000
virtual page address:f0100000        u/s=0           r/w=1
virtual page address:f0101000        u/s=0           r/w=1
virtual page address:f0102000        u/s=0           r/w=1
virtual page address:f0103000        u/s=0           r/w=1
```

### setpermission

`setpermission va [u|w] [0|1]`指令用来将`va`虚拟地址的权限位`u/s`或者`r/w`设置成`0`或者`1`。用`pgdir_walk`取得pte后设置即可。

代码如下：

```c
int
mon_setpermission(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 4) {
		cprintf("setpermission error: the number of arguments should be 2.\n");
		cprintf("Usage: setpermission va [u|w] [0|1]\n");
		return 0;
	}
	uint32_t va = strtol(argv[1], NULL, 0);
	pte_t *pte = pgdir_walk(kern_pgdir, (void *) va, 0);
	if (!pte) cprintf("Virtual address %x doesn't exist.\n");
	else {
		uint32_t x = argv[3][0] - '0';
		cprintf("The corresponding virtual page address is %x\n", va & (~0xFFF));
		cprintf("Old Permissions: u/s=%d r/w=%d\n",
						(bool)(*pte & PTE_U), (bool)(*pte & PTE_W));
		if (argv[2][0] == 'u') {
			if (x == 0) *pte = *pte & ~PTE_U;
			else *pte = *pte | PTE_U;
		}
		else if (argv[2][0] == 'w') {
			if (x == 0) *pte = *pte & ~PTE_W;
			else *pte = *pte | PTE_W;
		}
		cprintf("New Permissions: u/s=%d r/w=%d\n",
						(bool)(*pte & PTE_U), (bool)(*pte & PTE_W));
	}
	return 0;
}
```

示例如下：

```
K> setpermission 0xf0100000 u 1
The corresponding virtual page address is f0100000
Old Permissions: u/s=0 r/w=1
New Permissions: u/s=1 r/w=1
```

### dumpcontents

`dumpcontents va_begin va_end`指令用来展示虚拟内存`va_begin`到`va_end`的内容。由于现在已经开启了虚拟内存，只要依次打印即可。

代码如下：

```c
int
mon_dumpcontents(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
		cprintf("dumpcontents error: the number of arguments should be 2.\n");
		cprintf("Usage: dumpcontents va_begin va_end\n");
		return 0;
	}
	uint32_t begin = strtol(argv[1], NULL, 0), end = strtol(argv[2], NULL, 0);
	for (; begin <= end; begin++) {
		if (!(begin & 0xf)) cprintf("%x: ", begin);
		cprintf("%02x ", * (unsigned char*) begin);
		if (!((begin+1) & 0xf)) cprintf("\n");
	}
	cprintf("\n");
	return 0;
}
```

示例如下：

```
K> dumpcontents 0xf0100000 0xf010004f
f0100000: 02 b0 ad 1b 00 00 00 00 fe 4f 52 e4 66 c7 05 72 
f0100010: 04 00 00 34 12 b8 00 a0 11 00 0f 22 d8 0f 20 c0 
f0100020: 0d 01 00 01 80 0f 22 c0 b8 2f 00 10 f0 ff e0 bd 
f0100030: 00 00 00 00 bc 00 80 11 f0 e8 02 00 00 00 eb fe 
f0100040: f3 0f 1e fb 55 89 e5 53 83 ec 08 e8 0b 01 00 00
```

