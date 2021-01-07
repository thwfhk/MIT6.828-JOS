# Report for lab1

Wenhao Tang

选择做了challenge

[TOC]


## Environment Configuration

```
Hardware Environment:
Memory:         4GB
Processor:      Intel® Core™ i5-8259U CPU @ 2.30GHz × 2 
Graphics:       Intel Iris Plus Graphics 655
OS Type:        64 bit
Disk:           15GB

Software Environment:
OS:             Ubuntu 20.04.1 LTS
Gcc:            Gcc 9.3.0
Make:           GNU Make 4.2.1
Gdb:            GNU gdb 9.1

```

### Test Compiler Toolchain
```shell
$ objdump -i   # the 5th line say elf32-i386
$ gcc -m32 -print-libgcc-file-name
/usr/lib/gcc/x86_64-linux-gnu/9/32/libgcc.a
```

### QEMU Emulator
```shell
 # Clone the IAP 6.828 QEMU git repository
 $ git clone https://github.com/geofft/qemu.git
 $ cd qemu
 $ ./configure --disable-kvm --target-list="i386-softmmu x86_64-softmmu"
 $ make
 $ sudo make install
```

## Part 1: PC Bootstrap

### Simulating the x86
```shell
candy@ubuntu:~/6.828/lab$ make
+ as kern/entry.S
+ cc kern/entrypgdir.c
+ cc kern/init.c
+ cc kern/console.c
+ cc kern/monitor.c
+ cc kern/printf.c
+ cc kern/kdebug.c
+ cc lib/printfmt.c
+ cc lib/readline.c
+ cc lib/string.c
+ ld obj/kern/kernel
+ as boot/boot.S
+ cc -Os boot/main.c
+ ld boot/boot
boot block is 390 bytes (max 510)
+ mk obj/kern/kernel.img
```
After compiling, we now have our boot loader(obj/boot/boot) and out kernel(obj/kern/kernel), So where is the disk?
Actually the `kernel.img` is the disk image, which is acting as the virtual disk here. From kern/Makefrag we can see that both our boot loader and kernel have been written to the image(using the `dd` command).

Now we can running the QEMU like running a real PC.
```shell
candy@ubuntu:~/6.828/lab$ make qemu-nox
***
*** Use Ctrl-a x to exit qemu
***
qemu-system-i386 -nographic -drive file=obj/kern/kernel.img,index=0,media=disk,format=raw -serial mon:stdio -gdb tcp::26000 -D qemu.log
6828 decimal is XXX octal!
entering test_backtrace 5
entering test_backtrace 4
entering test_backtrace 3
entering test_backtrace 2
entering test_backtrace 1
entering test_backtrace 0
leaving test_backtrace 0
leaving test_backtrace 1
leaving test_backtrace 2
leaving test_backtrace 3
leaving test_backtrace 4
leaving test_backtrace 5
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K>
```

## Part 2: Boot Loader

### Exercise 3.

#### questions:

> Q1: At what point does the processor start executing 32-bit code? What exactly causes the switch from 16- to 32-bit mode?

`boot.S`中如下几行进行了real mode到32-bit protected mode的转换。

```assembly
  lgdt    gdtdesc
  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax # cr0的最低位pe表示protected mode是否开启
  movl    %eax, %cr0
  ljmp    $PROT_MODE_CSEG, $protcseg
```

首先`lgdt gdtdesc`载入了全局描述符表，然后三条指令将register `%cr0`的最低位设置为1，表示开启protected mode。

此时`ljmp`指令已经是在32-bit protected mode下运行了，selector `$PROT_MODE_CSEG`现在是描述符表的索引。观察代码中描述符表定义可知code segment条目的索引恰好是`PROT_MODE_CSEG`的值`0x8`，并且这个条目`SEG(STA_X|STA_R, 0x0, 0xffffffff)`告诉我们code segment是从`0x0`开始的，因此切换到32-bit mode后指令地址并没有改变。

使用`ljmp`的目的是设置`CS`的值，由于selector的含义已经变了，需要把`CS`设置成`$PROT_MODE_CSEG`。同样的原因，接下来几条指令是设置其他segment register的值。

> Q2: What is the *last* instruction of the boot loader executed, and what is the *first* instruction of the kernel it just loaded?

查看`boot.asm`和`kernel.asm`：

boot loader的最后一条指令是`0x7d81:	call   *0x10018`;

kernel的第一条指令是`0x10000c:	movw   $0x1234,0x472`.

> Q3: Where* is the first instruction of the kernel?

位置是`0x10000c`

> Q4: How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?

boot loader先读入了ELF格式内核的ELF header，然后从ELF header里得到program header table的位置以及表项数量，依次读取program header table中各个segment。

### Exercise 5.

> Trace through the first few instructions of the boot loader again and identify the first instruction that would "break" or otherwise do the wrong thing if you were to get the boot loader's link address wrong.

`-Ttext 0x7000`只修改了boot loader的link address，load address仍然是`0x7c00`，所以BIOS还会将boot loader载入到`0x7c00`处。

此时，`boo.S`运行到`  lgdt gdtdesc`时，会到`0x7064`位置找`gdtdesc`，但是`gdtdesc`实际上在`0x7c64`位置，导致失败，接下来`ljmp`就会报错了。

### Exercise 6.

> Reset the machine (exit QEMU/GDB and start them again). Examine the 8 words of memory at 0x00100000 at the point the BIOS enters the boot loader, and then again at the point the boot loader enters the kernel. Why are they different? What is there at the second breakpoint?

BIOS enters the boot loader:

```shell
(gdb) x /8x 0x100000
0x100000:	0x00000000	0x00000000	0x00000000	0x00000000
0x100010:	0x00000000	0x00000000	0x00000000	0x00000000
```

boot loader enters the kernel:

```
(gdb) x /8x 0x100000
0x100000:	0x1badb002	0x00000000	0xe4524ffe	0x7205c766
0x100010:	0x34000004	0x2000b812	0x220f0011	0xc0200fd8
```

不同的原因：刚进入boot loader时还没有载入kernel，离开boot loader时在`0x100000`处载入了kernel。

## Part 3: The Kernel

### Exercise 7.

> Use QEMU and GDB to trace into the JOS kernel and stop at the `movl %eax, %cr0`. Examine memory at 0x00100000 and at 0xf0100000. Now, single step over that instruction using the stepi GDB command. Again, examine memory at 0x00100000 and at 0xf0100000. Make sure you understand what just happened.

```shell
(gdb) si
=> 0x100025:	mov    %eax,%cr0
0x00100025 in ?? ()
(gdb) x /x 0x100000
0x100000:	0x1badb002
(gdb) x /x 0xf0100000
0xf0100000 <_start-268435468>:	0x00000000

(gdb) si
=> 0x100028:	mov    $0xf010002f,%eax
0x00100028 in ?? ()
(gdb) x /x 0x100000
0x100000:	0x1badb002
(gdb) x /x 0xf0100000
0xf0100000 <_start-268435468>:	0x1badb002
```

可以发现执行`mov %eax,%cr0`后`0xf0100000`被映射到了`0x100000`, 因为这条mov指令将`%cr0`中的pg位置为1，开启了paging。

> What is the first instruction *after* the new mapping is established that would fail to work properly if the mapping weren't in place? Comment out the `movl %eax, %cr0` in `kern/entry.S`, trace into it, and see if you were right.

如果没有mapping，第一条失败的指令是`kern/entry.S`中68行的`	jmp *%eax`. 测试发现确实如此。

### Exercise 8.

```c
		case 'o':
			num = getuint(&ap, lflag);
			base = 8;
			goto number;
```

#### questions:

> Q1:  Explain the interface between `printf.c` and `console.c`. Specifically, what function does `console.c` export? How is this function used by`printf.c`?

`console.c`提供了`void cputchar(int c)`函数，这个函数用于在console中输出一个字符，`printf.c`中使用它实现输出字符这一基本功能，封装后作为`putch`提供给`vprintfmt`.

> Q2: xplain the following from `console.c`
>
> ```c
> if (crt_pos >= CRT_SIZE) {
>   int i;
>   memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
>   for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
>           crt_buf[i] = 0x0700 | ' ';
>   crt_pos -= CRT_COLS;
> }
> ```

这一段代码在`crt_pos`（表示当前光标位置）到达屏幕边缘或超出屏幕（即没有空再写内容时）触发，将第2行到第`CRT_ROWS`行的内容向上移动了一行，这样就覆盖了原来的第一行，空出了最后一行，并将最后一行清空，然后将`crt_pos`向前移动了一行的位置。效果就是写满屏幕后屏幕内容会向上滚动一行。

> Q3: Trace the execution of the following code step-by-step:
>
> ```
> int x = 1, y = 3, z = 4;
> cprintf("x %d, y %x, z %d\n", x, y, z);
> ```
>
> - In the call to `cprintf()`, to what does `fmt` point? To what does `ap` point?
> - List (in order of execution) each call to `cons_putc`, `va_arg`, and `vcprintf`. For `cons_putc`, list its argument as well. For `va_arg`, list what `ap` points to before and after the call. For `vcprintf` list the values of its two arguments.

第一问：`fmt=0xf0101b72` 是第一个参数格式字符串; `ap=0xf010ffd4` 是后面的不定长参数列表。

第二问：

* `vcprintf (fmt=0xf0101b72 "x %d, y %x, z %d\n", ap=0xf010ffd4 "\001")`
* `cons_putc (c=120)`
* `cons_putc (c=32)`
* `va_arg`, 从`ap=0xf010ffd4`变成`ap=0xf010ffd8`
* `cons_putc (c=49)`
* `cons_putc (c=44)`
* `cons_putc (c=32)`
* `cons_putc (c=121)`
* `cons_putc (c=32)`
* `va_arg`, 从`ap=0xf010ffd8`变成`ap=0xf010ffdc`
* `cons_putc (c=51)`
* `cons_putc (c=44)`
* `cons_putc (c=32)`
* `cons_putc (c=122)`
* `cons_putc (c=32)`
* `va_arg`, 从`ap=0xf010ffdc`变成`ap=0xf010ffe0`
* `cons_putc (c=52)`
* `cons_putc (c=10)`

> Q4: Run the following code.
>
> ```
>     unsigned int i = 0x00646c72;
>     cprintf("H%x Wo%s", 57616, &i);
> ```
>
> What is the output? Explain how this output is arrived at in the step-by-step manner of the previous exercise. [Here's an ASCII table](http://web.cs.mun.ca/~michael/c/ascii-table.html)
>
> The output depends on that fact that the x86 is little-endian. If the x86 were instead big-endian what would you set `i` to in order to yield the same output? Would you need to change `57616` to a different value?

输出`He110 World`.  前面的`e110`是因为57616的16进制就是`0xe110`；后面的`rld`是将无符号数i解释成字符的结果：`i = 0x00646c72`，由于x86小端法，在内存中就是`72 6c 64 00`，对应的ascii字符串恰好是`rld\0`。

如果x86是大端法的话，`i = 0x726c6400`即可，无需改变57616。

> Q5: In the following code, what is going to be printed after `'y='`
>
> ```
>     cprintf("x=%d y=%d", 3);
> ```

在我的环境下，输出`x=3 y=1600`。由于后面的不定长参数列表里只有一个参数3，所以`ap`里只有一个参数，输出第二个`%d`时会拿出`ap`之后的一块4 bytes内存来输出。

> Q6: Let's say that GCC changed its calling convention so that it pushed arguments on the stack in declaration order, so that the last argument is pushed last. How would you have to change cprintf or its interface so that it would still be possible to pass it a variable number of arguments?

改成`cprintf(const char *fmt, ..., int len)`, len表示不定长参数列表的参数数量。

### Challenge

> *Challenge* Enhance the console to allow text to be printed in different colors. The traditional way to do this is to make it interpret [ANSI escape sequences](http://rrbrandt.dee.ufcg.edu.br/en/docs/ansi/) embedded in the text strings printed to the console, but you may use any mechanism you like. There is plenty of information on [the 6.828 reference page](https://pdos.csail.mit.edu/6.828/2018/reference.html) and elsewhere on the web on programming the VGA display hardware. If you're feeling really adventurous, you could try switching the VGA hardware into a graphics mode and making the console draw text onto the graphical frame buffer.

观察`console.c`里的`cga_putc`，发现前几行是在设置字体颜色，定义变量`cga_textcolor`表示字体颜色并如下修改代码：

```c
if (!(c & ~0xFF))
	c |= cga_textcolor;
```

接下来，只要修改`printfmt.c`中的`vprintfmt`，加上对ANSI escape sequences的解析就好了。因为ANSI escape sequences太复杂了，只实现字体颜色的话不需要这么复杂，所以我使用了一种简化的语法：在字符串中加入`\ex`来设置之后的字体颜色，其中x是一个`0-7`的数字，将x看成二进制，三个二进制位分别表示rgb，0的话就是0，1的话就是170。所以现在想打印红色的red单词就是`"\e4red"`。

`vprintfmt`前几行如下修改：

```c
vprintfmt(void (*putch)(int, void*), void *putdat, const char *fmt, va_list ap)
{
	register const char *p;
	register int ch, err;
	unsigned long long num;
	int base, lflag, width, precision, altflag;
	char padc;

	while (1) {
		while ((ch = *(unsigned char *) fmt++) != '%') {
			if (ch == '\0')
				return;
			if (ch == '\e') {
				ch = *(unsigned char *) fmt++;
				if (ch < '0' || ch > '7') ch = '7';
				cga_textcolor = (ch -'0') << 8;
			}
			else
				putch(ch, putdat);
		}
```

在`monitor.c`中加入了一句`	cprintf("\e1Welcome \e2to \e3the \e4JOS \e5kernel \e6monitor!\e7\n");`来展示效果，如下图所示

![image-20201006184547892](typora_images/lab1.assets/image-20201006184547892.png)

### The Stack

### Exercise 9.

> **Exercise 9.** Determine where the kernel initializes its stack, and exactly where in memory its stack is located. How does the kernel reserve space for its stack? And at which "end" of this reserved area is the stack pointer initialized to point to?

`entry.S`中如下两条语句初始化了stack：

```assembly
	movl	$0x0,%ebp
	movl	$(bootstacktop),%esp
```

查看`kernel.asm`:

```assembly
	# Set the stack pointer
	movl	$(bootstacktop),%esp
f0100034:	bc 00 10 11 f0       	mov    $0xf0111000,%esp
```

可知栈顶在内存中的位置是`0xf0110000`，并且栈的大小是`KSTKSIZE = 8 * 4096 = 32 KB`，所以栈的位置是`0xf0108000 - 0xf0110000`。

Kernel通过在`entry.S`的`.data`段声明来为stack留出空间。

x86中栈是向下生长的，stack pointer一开始在栈顶，也就是`0xf0110000`位置。

### Exercise 10.

> **Exercise 10.** To become familiar with the C calling conventions on the x86, find the address of the `test_backtrace`function in `obj/kern/kernel.asm`, set a breakpoint there, and examine what happens each time it gets called after the kernel starts. How many 32-bit words does each recursive nesting level of `test_backtrace` push on the stack, and what are those words?

函数栈帧包含最开始压入栈中的`%rbp`和最后（可能）调用函数时压入栈中的return address。

* test_backtrace(5): `0xf010ffdc - 0xf010ffbc`（包含调用test_backtrace(4)时压入栈中的返回地址）
* test_backtrace(4): `0xf010ffbc - 0xf010ff9c` （包含调用test_backtrace(3)时压入栈中的返回地址）
* test_backtrace(3): `0xf010ff9c - 0xf010ff7c`（包含调用test_backtrace(2)时压入栈中的返回地址）
* test_backtrace(2): `0xf010ff7c - 0xf010ff5c`（包含调用test_backtrace(1)时压入栈中的返回地址）
* test_backtrace(1): `0xf010ff5c - 0xf010ff3c`（包含调用test_backtrace(0)时压入栈中的返回地址）
* test_backtrace(0): `0xf010ff3c - 0xf010ff20`（不再递归调用，所以与之前相比少了一个4字节返回地址）

### Exercise 11.

> **Exercise 11.** Implement the backtrace function as specified above. Use the same format as in the example, since otherwise the grading script will be confused. When you think you have it working right, run make grade to see if its output conforms to what our grading script expects, and fix it if it doesn't. *After* you have handed in your Lab 1 code, you are welcome to change the output format of the backtrace function any way you like.

对于每个函数栈帧，我们要输出它的栈底（压入上个`%ebp`之后的）`ebp`，这个函数结束后的返回地址`eip`，以及传给它的在内存中的5个参数。

代码如下所示：

```c
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	cprintf("Stack backtrace:\n");
	int ebp = read_ebp();
	// int last_ebp = *((int*)ebp);
	while (ebp) {
		int* ebp_ptr = (int*) ebp;
		cprintf("  ebp %08x", ebp);
		cprintf("  eip %08x", *(ebp_ptr + 1));
		cprintf("  args");
		for (int i = 2; i <= 6; i++)
			cprintf(" %08x", *(ebp_ptr + i));
		cprintf("\n");
		ebp = *ebp_ptr;
	}
	return 0;
}
```

### Exercise 12.

> **Exercise 12.** Modify your stack backtrace function to display, for each `eip`, the function name, source file name, and line number corresponding to that `eip`.
>
> Complete the implementation of `debuginfo_eip` by inserting the call to `stab_binsearch` to find the line number for an address.
>
> Add a `backtrace` command to the kernel monitor, and extend your implementation of `mon_backtrace` to call `debuginfo_eip` and print a line for each stack frame.

在`debuginfo_eip`中填充如下代码：

```c
	stab_binsearch(stabs, &lline, &rline, N_SLINE, addr);
	if (lline <= rline) {
		info->eip_line = stabs[lline].n_desc; // line number保存在desc field里
	}
	else {
		return -1;
	}
```

`mon_backtrace`的实现如下：

```c
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
```

并在commands数组中加入如下条目：

```c
	{ "backtrace", "Display the stack backtrace", mon_backtrace }
```

输入`backtrace`命令的效果如下所示：

```shell
K> backtrace
Stack backtrace:
  ebp f0110f58  eip f0100b39  args 00000001 f0110f80 00000000 f0100ba1 f0100b48
         kern/monitor.c:143: monitor+343
  ebp f0110fd8  eip f0100109  args 00000000 00001aac 00000640 00000000 00000000
         kern/init.c:43: i386_init+95
  ebp f0110ff8  eip f010003e  args 00000003 00001003 00002003 00003003 00004003
         kern/entry.S:83: <unknown>+0
```



## This Complete The Lab.