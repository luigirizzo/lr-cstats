/* SPDX-License-Identifier: Apache-2.0 */

/* various forms of retpolines */
//extern void _x86_indirect_thunk_r11(void);
//extern void func_x2(void);
//extern void func_x3(void);
// In memory
//  cat /proc/kallsyms | grep _x86_indirect_thunk_r11

/* lr_retp() is just a wrapper for assembly code for the retpoline */
void lr_retp() {
  asm volatile(
    //	"	.globl func_x; .type func_x,@function;"
    //	"	.globl func_x2; .type func_x2,@function;"
    //	"	.globl func_x3; .type func_x3,@function;"
	"	.globl __x86_indirect_thunk_r11;"
	"	.type __x86_indirect_thunk_r11,@function;"
	"__x86_indirect_thunk_r11:"
    //	"	jmpq *%%r11;"	// cascadelake, indirect jump, 2 cycles
	"	lfence; jmpq *%%r11;"	// indirect jump, 2 cycles
	"	callq func_x3; "	// 40 cycles
	"func_x2: pause; jmp func_x2;"
	".align 16; func_x3: movq %%r11, (%%rsp); retq;" // skylake
	:::);
#if 0
 asm volatile("rdpmc": "=a" (low), "=d" (high): "c" (reg));
        return low | ((uint64_t)(high) << 32);

000000000403000 <__llvm_retpoline_r11>:
  403000:       e8 0b 00 00 00          callq  403010 <__llvm_retpoline_r11+0x10>
  403005:       f3 90                   pause  
  403007:       0f ae e8                lfence 
  40300a:       e9 f6 ff ff ff          jmpq   403005 <__llvm_retpoline_r11+0x5>
  40300f:       90                      nop
  403010:       4c 89 1c 24             mov    %r11,(%rsp)
  403014:       c3                      retq   
  403015:       66 2e 0f 1f 84 00 00    nopw   %cs:0x0(%rax,%rax,1)
  40301c:       00 00 00 
  40301f:       90                      nop
#endif

}

/* Target for an external call */
void foo(void)
{
}
