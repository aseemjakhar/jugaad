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

#ifndef _jugaad_h_
#define _jugaad_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 
 * Random default address used for overwriting remote process memory area for mmap shellcode.
 * Note that the remote memory area once used by jugaad is updated back to it's original
 * data along with the register values. This makes sure that once we have injected the
 * thread the remote process can resume its execution from where we stopped it.
 */
#define DEFAULT_BKPADDR  0x08048480

/* Default stack size for thread */
#define DEFAULT_STKSIZE  10000
/* 
 * Default clone and mmap arguments pass to the srespective system calls if none
 * is pase sed by the caller
 */
#define DEFAULT_TFLAGS   CLONE_THREAD | CLONE_VM | CLONE_SIGHAND
#define DEFAULT_MPROT    PROT_EXEC | PROT_READ | PROT_WRITE
#define DEFAULT_MFLAGS   MAP_PRIVATE | MAP_ANONYMOUS

/*
 * An attempt to create CreateRemoteThread() for *nix platform. This function creates
 * a thread inside a remote process and executes the payload specified by the caller
 * within the context of that thread. The usual unix security permissions apply to this
 * function as well i.e. can't create thread within a remote process for which you don't 
 * have rights to ptrace(). It does this by allocating memory within the remote process
 * using mmap2 system call(shellcode) for the thread stack and the thread code. The thread
 * code is a shellcode comprising of clone system call, the caller specified payload and
 * exit system call(for thread exit) so, the caller need only pass the shellcode that
 * it wants to execute and not worry about thread exit and other things. Note that since
 * the payload executes as a thread, it must be thread-aware, adhere to common threading
 * rules and not mess with the main thread if it wants to survive. 
 * 
 * Note that in windows CreateRemoteThread() the caller is required to previously arrange
 * for the payload(lpStartAddress argument) to be present in the remote process. 
 * In jugaad, create_remote_thread() takes care of injecting the payload as well.  
 *
 * @param  pid          [IN] The process identifier of the target process.
 *
 * @param  stack_size   [IN] The size of the stack (in bytes) to be created for the thread
 *                           within the target process. If the stack_size is smaller than
 *                           the DEFAULT_STKSIZE, it is reset to DEFAULT_STKSIZE. 
 *
 * @param  tpayload     [IN] The payload (shellcode) to be executed within the thread.
 *                           The shellcode may contain NULL bytes. In other words there are
 *                           no restricted characters for the shellcode.
 *
 * @param  tpsize       [IN] The size of the thread payload in bytes. It should not include
 *                           the termintating NULL in the string if any as a convention.
 *
 * @param  thread_flags [IN] Flags used to specify what is shared between injected thread and 
 *                           the main thread. This argument is directly passed to clone system
 *                           call. For exact details about the values of this argument read
 *                           clone manual page(man clone), specifically the flags argument values.
 *                           If this argument is zero, then this function uses the default
 *                           flags: DEFAULT_TFLAGS. When in doubt just set it to zero. 
 *
 * @param  mmap_prot    [IN] Memory protection of the mapping created for the payload. For exact
 *                           details about the values of this argument read mmap manual page(man mmap),
 *                           specifically the prot argument values. If this argument is zero then
 *                           this function uses DEFAULT_MPROT. When in doubt just set it to zero.
 *
 * @param  mmap_flags   [IN] mmap flags for the mapping. For exact details about the values of this
 *                           argument read mmap manual page(man mmap), specifically the 'flags' 
 *                           argument values. If this argument is zero then this function uses 
 *                           DEFAULT_MFLAGS. When in doubt just set it to zero.
 *                           
 * @param  bkpaddr      [IN] The location that the caller wants to use for temporary injection
 *                           of the meta code that does the memory allocation. If this argument
 *                           is NULL then this function uses DEFAULT_BKPADDR. It is recommended
 *                           to set it to NULL unless the caller specifically wants to use a
 *                           predefined location in the remote process.
 *
 * @return  Zero on success, non-zero otherwise.
 *
 */
int create_remote_thread_ex(pid_t pid,
                            size_t stack_size,
                            unsigned char * tpayload,
                            size_t tpsize,
                            int thread_flags,
                            int mmap_prot,
                            int mmap_flags,
                            void * bkpaddr);

int create_remote_thread(pid_t pid,
                         size_t stack_size,
                         unsigned char * tpayload,
                         size_t tpsize);

/*
 * Returns a static string specifying jugaad version
 *
 * @return  version string
 */
char * jugaad_version(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _jugaad_h_ */
