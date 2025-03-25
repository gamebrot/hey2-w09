/*
 * Copyright (c) Honor Device Co., Ltd. 2023-2023. All rights reserved.
 * Description:dump code for undefined instruction issue
 * Author: mahulin
 * Create: 2023-11-7
 */

#include <micro_dump.h>
#include <linux/kbuild.h>

static __maybe_unused struct pt_regs *get_undef_regs(struct pt_regs *regs)
{
	struct stackframe frame;
	char buf[64] = {0};

	frame.fp = regs->regs[29];
	frame.pc = regs->pc;

	do {
		sprintf_s(buf, sizeof(buf), "%ps", (void *)(uintptr_t)frame.pc);
		if (!strcmp(buf, "el1_undef"))
			return (struct pt_regs *)(frame.fp -
						  offsetof(struct pt_regs,
							   stackframe));
	} while (!common_unwind_frame(NULL, &frame));

	return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
/* In line with aarch64_insn_read from arch/arm64/kernel/insn.c */
static unsigned int read_insn(void *addr, unsigned int *insnp)
{
	unsigned int ret, val;

	ret = copy_from_kernel_nofault(&val, addr, AARCH64_INSN_SIZE);
	if (!ret)
		*insnp = val;

	return ret;
}
#endif

/* In line with dump_kernel_instr from arch/arm64/kernel/traps.c */
static void dump_instr(struct pt_regs *regs)
{
	unsigned long addr = regs->pc;
	char str[sizeof("00000000 ") * 5 + 2 + 1], *p = str;
	int i;

	if (user_mode(regs))
		return;

	for (i = -4; i < 1; i++) {
		unsigned int val, bad;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		bad = read_insn(&((unsigned int *)(uintptr_t)addr)[i], &val);
#else
		bad = get_user(val, &((unsigned int *)(uintptr_t)addr)[i]);
#endif

		if (!bad) {
			p += sprintf_s(p, sizeof(str),
				       i == 0 ? "(%08x) " : "%08x ", val);
		} else {
			p += sprintf_s(p, sizeof(str), "bad PC value");
			break;
		}
	}

	MD_PRINT("Code: %s\n", str);
}

#ifdef CONFIG_HN_MICRODUMP_GKI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
void microdump_instr_vh(void *ignore, struct pt_regs *regs)
#else
void microdump_instr_vh(void *ignore, struct pt_regs *regs, bool user)
#endif
{
	dump_instr(regs);
}

void microdump_instr(struct pt_regs *regs)
{
}
#else
void microdump_instr(struct pt_regs *regs)
{
	struct pt_regs *undef_regs;

	undef_regs = get_undef_regs(regs);
	if (undef_regs)
		dump_instr(undef_regs);
}
#endif
