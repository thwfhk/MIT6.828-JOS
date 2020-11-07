// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display the stack backtrace", mon_backtrace },
	{ "showmappings", "Display the physical addresses and permissions of virtual addresses",
		mon_showmappings },
	{ "setpermission", "Change the permission of a virtual address",
		mon_setpermission },
	{ "dumpcontents", "Display the constents of a range of virtual addresses",
		mon_dumpcontents }
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	cprintf("Stack backtrace:\n");
	int ebp = read_ebp();
	// int last_ebp = *((int*)ebp);
	while (ebp) {
		int* ebp_ptr = (int*) ebp;
		int eip = *(ebp_ptr + 1);
		cprintf("  ebp %08x", ebp);
		cprintf("  eip %08x", eip);
		cprintf("  args");
		for (int i = 2; i <= 6; i++)
			cprintf(" %08x", *(ebp_ptr + i));
		cprintf("\n");
		struct Eipdebuginfo infoData;
		struct Eipdebuginfo *info = &infoData;
		debuginfo_eip(eip, info);
		cprintf("         %s:%d: ", info->eip_file, info->eip_line);
		cprintf("%.*s", info->eip_fn_namelen, info->eip_fn_name);
		cprintf("+%d", eip - info->eip_fn_addr);
		cprintf("\n");
		ebp = *ebp_ptr;
	}
	return 0;
}

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



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("\e1Welcome \e2to \e3the \e4JOS \e5kernel \e6monitor!\e7\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
