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


#ifndef _debug_h_
#define _debug_h_

#include <stdio.h>
#include <stdlib.h>

#ifdef DEBUG
  #define DPRINT(format, ...)   printf("%s(): " format, __FUNCTION__, ##__VA_ARGS__)
  #define DENTER()              printf("%s(): ENTERED\n", __FUNCTION__)
  #define DEXIT()               printf("%s(): EXITING\n", __FUNCTION__)

  #define DASKQUIT(pid)                                                             \
          {                                                                         \
              char ans[10] = {0};                                                   \
              while(1) {                                                            \
                  printf("Detach and quit?[y/n]: ");                                \
                  gets(ans);                                                        \
                  if (!strncmp(ans,"y", sizeof(ans) - 1) ||                         \
                      !strncmp(ans, "Y", sizeof(ans) - 1)) {                        \
                      if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {             \
                          DPRINT("Couldn't Detach from process(%d) error(%d:%s)\n", \
                                 pid,                                               \
                                 errno,                                             \
                                 strerror(errno));                                  \
                      }                                                             \
                      exit(0);                                                      \
                  }                                                                 \
                  else if (!strncmp(ans,"n", sizeof(ans) - 1) ||                    \
                           !strncmp(ans, "N", sizeof(ans) - 1)) {                   \
                      break;                                                        \
                  }                                                                 \
              }                                                                     \
          }


  #define DPRINTHEX(str, size, format, ...)                         \
          {   printf("%s(): " format, __FUNCTION__, ##__VA_ARGS__); \
              int i = 0;                                            \
              for (i = 0; i < size; i++) {                          \
                  printf(" 0x%x", (unsigned char)str[i]);           \
              }                                                     \
              printf("\n");                                         \
          }
#else
  #define DPRINT(format, ...)
  #define DENTER()
  #define DEXIT()

  #define DASKQUIT(pid)
  #define DPRINTHEX(str, size, format, ...)
#endif /* DEBUG */

#endif /* _debug_h_ */

