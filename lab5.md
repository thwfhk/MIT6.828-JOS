# Report for lab5

Wenhao Tang, 1800013088

[TOC]

### File System Preliminaries

JOS中的file system做了简化，不使用inode，直接将file和sub-directory的meta-data存在了directory entry中。file和directory都被分成一些data blocks来储存。

File system隐藏了blocks的储存方式，提供了在文件任意偏移进行读写的接口。

大多数disk提供**sector**粒度的读写，JOS中sector的大小是512 bytes.

File system以**block**为单位存储，block的大小必须是sector大小的倍数，JOS中block的大小是***4KB***（和page一样大）。

JOS有一个superblock，在block 1，存放了blocks的数量、root directory的File structure等信息。

Block0中存放boot loaders和partition tables.

JOS中一个File（包括regular file和directory）最多有10个direct blocks，1024个indirect blocks。directory的data blocks中的内容被解释为一系列File structure.



### Exercise 1

> Exercise 1. i386_init identiﬁes the ﬁle system environment by passing the type ENV_TYPE_FS to your environment creation function, env_create. Modify env_create in env.c, so that it gives the ﬁle system environment I/O privilege, but never gives that privilege to any other environment.

JOS将IDE disk driver实现在了用户file system environment中，使用**PIO-based disk access**。

JOS将IDE disk driver实现在了用户file system environment中，使用PIO-based disk access。

这里要给file system environment执行device I/O instruction (如`IN, OUT`)的权限，只要在`env_create`里设置权限位即可。

```c
	if (type == ENV_TYPE_FS) {
		e->env_tf.tf_eflags |= FL_IOPL_3;
	}
```

#### Question

不需要。因为每个environment的eflags是独有的，不会相互影响。

### Exercise 2

> Exercise 2. Implement the bc_pgfault and flush_block functions in fs/bc.c. 
>

file system environment中保留了`[DISKMAP, DISKMAP+DISKMAX)`的3GB虚拟地址空间来映射整个disk，作为block cache。这里使用了demand paging，发生page fault时才分配pages并从disk读入。

这里要实现`bc_pgfault`和`flush_block`。

`bc_pgfault`给对应block分配page并读入，`flush_block`将修改后的page（检查dirty位）写回到磁盘上的block中。代码如下：

```c
	// bc_pgfault:
	void* start = (void*)ROUNDDOWN((intptr_t) addr, PGSIZE);
	if ((r = sys_page_alloc(0, start, PTE_P | PTE_U | PTE_W)) < 0)
		panic("in bc_pgfault, sys_page_alloc: %e", r);
	if ((r = ide_read(blockno * (BLKSIZE/SECTSIZE), start, BLKSIZE/SECTSIZE)) < 0)
		panic("in bc_pgfault, ide_read: %e", r);

	// flush_block:
	int r;
	void* start = (void*)ROUNDDOWN((intptr_t) addr, PGSIZE);
	if (va_is_mapped(start) && va_is_dirty(start)) {
		if ((r = ide_write(blockno * (BLKSIZE/SECTSIZE), start, BLKSIZE/SECTSIZE)) < 0)
			panic("in bc_pgfault, ide_write: %e", r);
		sys_page_map(0, start, 0, start, PTE_SYSCALL);
	}
```

### Exercise 3

> Exercise 3. Use free_block as a model to implement alloc_block in fs/fs.c, which should ﬁnd a free disk block in the bitmap, mark it used, and return the number of that block. When you allocate a block, you should immediately ﬂush the changed bitmap block to disk with flush_block, to help ﬁle system consistency.

JOS中使用bitmap来保存每个block是否正在被使用。整个disk的结构如图所示：

![Disk layout](typora_images/lab5.assets/disk.png)

这里要实现`alloc_block`函数，找到一个free的block然后返回其block number，并flush一下bitmap所在的block。

```c
int
alloc_block(void)
{
	// The bitmap consists of one or more blocks.  A single bitmap block
	// contains the in-use bits for BLKBITSIZE blocks.  There are
	// super->s_nblocks blocks in the disk altogether.

	// LAB 5: Your code here.
	for (uint32_t blockno = 0; blockno < super->s_nblocks; blockno++) {
		if (block_is_free(blockno)) {
			bitmap[blockno/32] &= ~(1<<(blockno%32));
			flush_block(&bitmap[blockno/32]);
			return blockno;
		}
	}
	return -E_NO_DISK;
}
```

### Exercise 4

> Exercise 4. Implement file_block_walk and file_get_block. file_block_walk maps from a block offset within a ﬁle to the pointer for that block in the struct File or the indirect block, very much like what pgdir_walk did for page tables. file_get_block goes one step further and maps to the actual disk block, allocating a new one if necessary.

`file_block_walk`函数查询file f中第filebno个data block的entry（entry中保存的是这个block的编号），并将这个entry的***地址***保存到`*ppdiskbno`中（它是`uint32_t*`类型）；`alloc=1`，如果indirect block还未分配则会分配。

`file_get_block`函数查询file f中第filebno个data block的磁盘地址，并将这个地址保存到`*blk`中（它是`char*`类型）；如果第filebno个block还未分配则会分配。

```c
static int
file_block_walk(struct File *f, uint32_t filebno, uint32_t **ppdiskbno, bool alloc)
{
	// LAB 5: Your code here.
	int r;
	if (filebno >= NDIRECT + NINDIRECT)
		return -E_INVAL;
	if (filebno < NDIRECT) {
		*ppdiskbno = f->f_direct + filebno;
		return 0;
	}
	else {
		if (!f->f_indirect && !alloc)
			return -E_NOT_FOUND;
		if (!f->f_indirect) {
			if ((r = alloc_block()) < 0)
				return -E_NO_DISK;
			f->f_indirect = r;
			memset(diskaddr(r), 0, BLKSIZE); // we need to clear it
			flush_block(diskaddr(r));
		}
		// NOTE: each entry is a uint32_t
		*ppdiskbno = (uint32_t*)diskaddr(f->f_indirect) + (filebno - NDIRECT);
		return 0;
	}
}
int
file_get_block(struct File *f, uint32_t filebno, char **blk)
{
	// LAB 5: Your code here.
	int r;
	uint32_t* pdiskno;
	if ((r = file_block_walk(f, filebno, &pdiskno, true)) < 0)
		return r;
	if (*pdiskno == 0) { // this block is not allocated
		if ((r = alloc_block()) < 0)
			return -E_NO_DISK;
		*pdiskno = r;
		memset(diskaddr(r), 0, BLKSIZE); // we need to clear it
		flush_block(diskaddr(r));
	}
	*blk = diskaddr(*pdiskno);
	return 0;
}
```

### Exercise 5

> Exercise 5. Implement serve_read in fs/serv.c.

JOS中使用**remote procedure call(RPC)**来实现其他environment调用FS environment完成disk access。client向server发起ipc，server完成任务后也会回复一个ipc。client发起ipc时用32-bit整数表示request type，并用一个`union Fsipc`来传递参数，这个union所在的page的地址永远是`fsipcbuf`。server只需要把读的信息写到这个page上就行了（因为server也映射了这个物理页）。

以read为例，一次调用过程如下图所示：

```
 Regular env           FS env
   +---------------+   +---------------+
   |      read     |   |   file_read   |
   |   (lib/fd.c)  |   |   (fs/fs.c)   |
...|.......|.......|...|.......^.......|...............
   |       v       |   |       |       | RPC mechanism
   |  devfile_read |   |  serve_read   |
   |  (lib/file.c) |   |  (fs/serv.c)  |
   |       |       |   |       ^       |
   |       v       |   |       |       |
   |     fsipc     |   |     serve     |
   |  (lib/file.c) |   |  (fs/serv.c)  |
   |       |       |   |       ^       |
   |       v       |   |       |       |
   |   ipc_send    |   |   ipc_recv    |
   |       |       |   |       ^       |
   +-------|-------+   +-------|-------+
           |                   |
           +-------------------+
```

file system environment循环接受信号，然后调用不同`serve_xxx()`函数来处理。这里要实现的是`fs/serv.c`中的`serve_read`函数，从`req_fileid`中file descriptor所指定的offset处开始读取`req_n`个字节，写到`ret_buf`中，并更新offset。

代码如下所示：

```c
int
serve_read(envid_t envid, union Fsipc *ipc)
{
	struct Fsreq_read *req = &ipc->read;
	struct Fsret_read *ret = &ipc->readRet;

	if (debug)
		cprintf("serve_read %08x %08x %08x\n", envid, req->req_fileid, req->req_n);

	// Lab 5: Your code here:
	struct OpenFile *o;
	int r;
	if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0)
		return r;
	if ((r = file_read(o->o_file, ret->ret_buf, req->req_n, o->o_fd->fd_offset)) < 0)
		return r;
	o->o_fd->fd_offset += r;
	return r;
}
```

### Exercise 6

> Exercise 6. Implement serve_write in fs/serv.c and devfile_write in lib/file.c.

`serve_write`函数和`serve_read`类似。

```c
int
serve_write(envid_t envid, struct Fsreq_write *req)
{
	if (debug)
		cprintf("serve_write %08x %08x %08x\n", envid, req->req_fileid, req->req_n);

	// LAB 5: Your code here.
	struct OpenFile *o;
	int r;
	if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0)
		return r;
	if ((r = file_write(o->o_file, req->req_buf, req->req_n, o->o_fd->fd_offset)) < 0)
		return r;
	o->o_fd->fd_offset += r;
	return r;
}
```

`devfile_write`函数类似已经给出的`devfile_read`，负责将参数放到`fsipcbuf`的`union Fsipc`中，然后调用`fsipc()`发送ipc信号（第二个参数传NULL是因为`fsipc()`中会自动处理page的地址）。

```c
static ssize_t
devfile_write(struct Fd *fd, const void *buf, size_t n)
{
	// Make an FSREQ_WRITE request to the file system server.  Be
	// careful: fsipcbuf.write.req_buf is only so large, but
	// remember that write is always allowed to write *fewer*
	// bytes than requested.
	// LAB 5: Your code here
	int r;
	fsipcbuf.write.req_fileid = fd->fd_file.id;
	fsipcbuf.write.req_n = n;
	memcpy(fsipcbuf.write.req_buf, buf, n);
	if ((r = fsipc(FSREQ_WRITE, NULL)) < 0)
		return r;
	assert(r <= n);
	assert(r <= PGSIZE - (sizeof(int) + sizeof(size_t)));
	return r;
}
```

### Exercise 7

> Exercise 7. spawn relies on the new syscall sys_env_set_trapframe to initialize the state of the newly created environment. Implement sys_env_set_trapframe in kern/syscall.c (don't forget to dispatch the new system call in syscall()).

JOS中使用`spawn()`来实现UNIX中`fork() + exec()`的功能。

这里要实现`sys_env_set_trapframe`这个系统调用，来设置某个env的trapframe。

```c
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	int r;
	struct Env *e;
	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	// cprintf("look: %d %d\n", curenv->env_id, e->env_id);
	user_mem_assert(curenv, tf, sizeof(struct Trapframe), 0);
	e->env_tf = *tf;
	e->env_tf.tf_cs |= 3;
	e->env_tf.tf_eflags |= FL_IF;
	e->env_tf.tf_eflags &= ~FL_IOPL_3;
	return 0;
}
```

### Exercise 8

> Exercise 8. Change duppage in lib/fork.c to follow the new convention. If the page table entry has the PTE_SHARE bit set, just copy the mapping directly. (You should use PTE_SYSCALL, not 0xfff, to mask out the relevant bits from the page table entry. 0xfff picks up the accessed and dirty bits as well.)
>
> Likewise, implement copy_shared_pages in lib/spawn.c. It should loop through all page table entries in the current process (just like fork did), copying any page mappings that have the PTE_SHARE bit set into the child process.

JOS中维护了一个file descriptor table，从`FDTABLE=0xD0000000`开始，最多32个fd，每个fd有1 page的地址空间。只有当对应fd被使用时这page地址空间才被映射。每个fd也有一个从`FILEDATA`开始的optional data page。

我们希望fd在`fork`和`spawn`的environments之间共享，方法是在在pte entry中加了一个`PTE_SHARE`位，来标识这个page是否共享。这个exercise让我们修改`lib/fork.c`中的`duppage()`和`lib/spawn.c`中的`copy_shared_pages()`来处理共享的情况。代码如下：

```c
// duppage
	if (pte & PTE_SHARE) {
		if ((r = sys_page_map(curenvid, addr, envid, addr, pte & PTE_SYSCALL)) < 0)
			return r;
	}
// copy_shared_pages
static int
copy_shared_pages(envid_t child)
{
	// LAB 5: Your code here.
	int r;
	for (uint32_t i = 0; i < UTOP; i += PGSIZE) {
		if ((uvpd[PDX(i)] & PTE_P) && (uvpt[PGNUM(i)] & PTE_P)
					&& (uvpt[PGNUM(i)] & PTE_SHARE)) {
		  if ((r = sys_page_map(0, (void*)i, child, (void*)i, uvpt[PGNUM(i)] & PTE_SYSCALL)) < 0)
				return r;
		}
	}
	return 0;
}
```

### Exercise 9

> Exercise 9. In your kern/trap.c, call kbd_intr to handle trap IRQ_OFFSET+IRQ_KBD and serial_intr to handle trap IRQ_OFFSET+IRQ_SERIAL.

在`trap_dispatch()`中处理键盘和串口输入。

```c
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_KBD) {
		lapic_eoi();
		kbd_intr();
		return;
	}
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SERIAL) {
		lapic_eoi();
		serial_intr();
		return;
	}
```

### Exercise 10

> The shell doesn't support I/O redirection. It would be nice to run sh <script instead of having to type in all the commands in the script by hand, as you did above. Add I/O redirection for < to user/sh.c.

这里要实现`user/sh.c`中的输入重定向功能，就是打开目标文件然后dup一下，和linux里一样。代码如下：

```c
			int fd = open(t, O_RDONLY);
			if (fd < 0) panic("input redirection error %e", fd);
			if (fd != 0) {
				dup(fd, 0);
				close(fd);
			}
```

## This completes the lab.





