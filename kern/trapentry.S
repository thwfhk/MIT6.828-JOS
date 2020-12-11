/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
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

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
.data
.global handlers
handlers:
TRAPHANDLER_NOEC(divide_handler, T_DIVIDE)
TRAPHANDLER_NOEC(debug_handler, T_DEBUG)
TRAPHANDLER_NOEC(nmi_handler, T_NMI)
TRAPHANDLER_NOEC(brkpt_handler, T_BRKPT)
TRAPHANDLER_NOEC(oflow_handler, T_OFLOW)
TRAPHANDLER_NOEC(bound_handler, T_BOUND)
TRAPHANDLER_NOEC(illop_handler, T_ILLOP)
TRAPHANDLER_NOEC(device_handler, T_DEVICE)
TRAPHANDLER(dblflt_handler, T_DBLFLT) /* 8 error code */
TRAPHANDLER_NOEC(coproc_handler, 9)
TRAPHANDLER(tss_handler, T_TSS) /* 10 error code */
TRAPHANDLER(segnp_handler, T_SEGNP) /* 11 error code */
TRAPHANDLER(stack_handler, T_STACK) /* 12 error code */
TRAPHANDLER(gpflt_handler, T_GPFLT) /* 13 error code */
TRAPHANDLER(pgflt_handler, T_PGFLT) /* 14 error code */
TRAPHANDLER_NOEC(res_handler, 15)
TRAPHANDLER_NOEC(fperr_handler, T_FPERR)
TRAPHANDLER(align_handler, T_ALIGN) /* 17 error code */
TRAPHANDLER_NOEC(mchk_handler, T_MCHK)
TRAPHANDLER_NOEC(simderr_handler, T_SIMDERR)

TRAPHANDLER_NOEC(syscall_handler, T_SYSCALL)

.data
.global irqhandlers
irqhandlers:
TRAPHANDLER_NOEC(irq0_handler, IRQ_OFFSET+0)
TRAPHANDLER_NOEC(irq1_handler, IRQ_OFFSET+1)
TRAPHANDLER_NOEC(irq2_handler, IRQ_OFFSET+2)
TRAPHANDLER_NOEC(irq3_handler, IRQ_OFFSET+3)
TRAPHANDLER_NOEC(irq4_handler, IRQ_OFFSET+4)
TRAPHANDLER_NOEC(irq5_handler, IRQ_OFFSET+5)
TRAPHANDLER_NOEC(irq6_handler, IRQ_OFFSET+6)
TRAPHANDLER_NOEC(irq7_handler, IRQ_OFFSET+7)
TRAPHANDLER_NOEC(irq8_handler, IRQ_OFFSET+8)
TRAPHANDLER_NOEC(irq9_handler, IRQ_OFFSET+9)
TRAPHANDLER_NOEC(irq10_handler, IRQ_OFFSET+10)
TRAPHANDLER_NOEC(irq11_handler, IRQ_OFFSET+11)
TRAPHANDLER_NOEC(irq12_handler, IRQ_OFFSET+12)
TRAPHANDLER_NOEC(irq13_handler, IRQ_OFFSET+13)
TRAPHANDLER_NOEC(irq14_handler, IRQ_OFFSET+14)
TRAPHANDLER_NOEC(irq15_handler, IRQ_OFFSET+15)

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