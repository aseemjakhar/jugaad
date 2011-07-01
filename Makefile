#
# Jugaad - Thread Injection Kit
#
# Author: Aseem Jakhar
# Organization: null - The open security community
# Websites: http://null.co.in   http://nullcon.net
#
# Copyright (c) 2011-2021 Aseem Jakhar <aseemjakhar_at_gmail.com>. All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

CC=gcc

CFLAGS=-DDEBUG -g
CFLAGS+=-Wall

SRC=shellcode.c jugaad.c
OBJ=$(SRC:.c=.o)
LIB=libjugaad.a

TESTPROG=testjugaad
TESTPROC=testproc

.PHONY: all lib clean

#make - create the library and the testing modules
all: lib
	$(CC) $(CFLAGS) -L./ -o $(TESTPROG) $(TESTPROG).c -ljugaad 
	$(CC) $(CFLAGS) -o $(TESTPROC) $(TESTPROC).c

#make lib - create only the library 
lib: $(LIB)

$(LIB): $(OBJ)
	ar crs $@ $(OBJ)

clean:
	rm -f $(OBJ) $(LIB) $(TESTPROG) $(TESTPROC)

