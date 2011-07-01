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

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include "shellcode.h"
#include "debug.h"


/*
 * Allocates and returns a shellcode object. It allocates both, the object
 * and the payload. Caller should call shellcode_free() when done using this
 * object.
 *
 * @param  psize [IN] The size to allocate for the payload.
 *
 */
struct shellcode * shellcode_alloc(size_t psize)
{
    struct shellcode * this = NULL;
    int ret = 0;

    DENTER();
    if (psize <= 0) {
        DPRINT("Wrong size(%d) passed\n", psize);
        ret = EINVAL;
        goto end;
    }

    this = malloc(sizeof(struct shellcode));
    if (this == NULL) {
        DPRINT("Couldn't allocate mem for this. Error(%d)\n", errno);
        ret = ENOMEM;
        goto end;
    }

    this->payload = malloc(psize);
    if (this->payload == NULL) {
        DPRINT("Couldn't allocate mem for this->payload. Error(%d)\n", errno);
        ret = ENOMEM;
        goto end;
    }
    this->psize = psize;

end:
    if (ret != 0 && this != NULL) {
        shellcode_free(&this);
    }
    DEXIT();
    return this;
}

/*
 * Creates a shellcode object from the given shellcode and size.
 *
 * @param  payload  [IN] The shellcode string.
 * @param  psize    [IN] The size of the shellcode string.
 *
 * @return  shellcode object pointer on success, NULL otherwise.
 */
struct shellcode * shellcode_copy(unsigned char * payload,
                                  size_t psize)
{
    struct shellcode * this = NULL;
    int ret = 0;

    DENTER();
    if (psize <= 0) {
        DPRINT("Wrong shellcode size(%d) passed\n", psize);
        ret = EINVAL;
        goto end;
    }
    if (payload == NULL) {
        DPRINT("NULL shellcode string passed\n");
        ret = EINVAL;
        goto end;
    }

    this = shellcode_alloc(psize);
    if (this == NULL) {
        DPRINT("Couldn't allocate mem for shellcode object\n");
        ret = ENOMEM;
        goto end;
    }

    memcpy(this->payload, payload, this->psize);

end:
    if (ret != 0 && this != NULL) {
        shellcode_free(&this);
    }
    DEXIT();
    return this;
}


/*
 * Appends the passed shelilcode to the shellcode object
 *
 * @param  this     [IN|OUT] The shellcode object that is to be appended 
 *                           with the shellcode string.
 * @param  payload  [IN]     The shellcode string that will be appended 
 *                           to the shellcode object payload.
 * @param  psize    [IN]     The size of the shellcode string.
 *
 * @return  Zero on success, non-zero otherwise.
 */
int  shellcode_append(struct shellcode * this,
                      unsigned char * payload,
                      size_t psize)
{
    int ret = 0;
    unsigned char * tmp = NULL;

    DENTER();
    if (this == NULL) {
        DPRINT("NULL shellcode object passed\n");
        ret = EINVAL;
        goto end;
    }
    if (payload == NULL) {
        DPRINT("NULL shellcode string passed\n");
        ret = EINVAL;
        goto end;
    }
    if (psize <= 0) {
        DPRINT("Invalid shellcode size(%d) passed\n", psize);
        ret = EINVAL;
        goto end;
    }

    /* set the size to zero if no payload is present */
    if (this->payload == NULL && this->psize != 0) {
        this->psize = 0;
    }

    tmp = realloc(this->payload, this->psize + psize);

    if (tmp == NULL) {
        DPRINT("Invalid shellcode size(%d) passed\n", psize);
        ret = ENOMEM;
        goto end;        
    }
    /* Append the passed shellcode */
    memcpy(tmp + this->psize, payload, psize);
    /* Set the new stuff */
    this->payload = tmp;
    this->psize = this->psize + psize;
end:

    DEXIT();
    return ret;
}


/*
 * This routine frees the shellcode object previously allocates and NULLs it out
 * so that the caller does not have to take the effort of setting it NULL everytime
 * an object is freed.
 *
 * @param  this [IN|OUT] Double Pointer to the object being freed. It sets the object 
 *                       pointer to NULL.
 */
void shellcode_free(struct shellcode ** this)
{
    DENTER();
    if ((this != NULL) && (*this != NULL)) {
        if ((*this)->payload != NULL) {
            free((*this)->payload);
        }
        else {
            DPRINT("Error: NULL (*this)->payload passed\n");
        }
        free(*this);
        *this = NULL;
    }
    else {
        DPRINT("Error: NULL this(%p) or *this passed\n", (this));
    }
    DEXIT();
}

/*
 * Creates a customized mmap2 shellcode with the caller specified arguments
 * to mmap2 system call. Note: For more detailed information on the arguments
 * refer to mmap manual page (man mmap). 
 *
 * @param  length [IN] The length of the mapping to be created.
 * @param  prot   [IN] The desired memory protection of the mapping.
 * @param  flags  [IN] Determines whether updates to the mapping are
 *                     visible to other processes mapping the same region 
 *                     and some other mapping related flags(man mmap).
 */
struct shellcode * shellcode_mmap2(size_t length,
                                   int prot,
                                   int flags)
{
    struct shellcode * this = NULL;
    int ret = 0;

    DENTER();
    /* 
     * Mild test for length, however practical length would be way more
     * than what is passed.
     */
    if (length < 1) {
        DPRINT("No memory desired from mmap2? length(%d)\n", length);
        ret = EINVAL;
        goto end;
    }

    /* Ignore the terminating NULL in the default mmap2 string by decreasing the size by 1 */
    this = shellcode_copy((unsigned char *)MMAP2_STUB, (sizeof(MMAP2_STUB) - 1));
    if (this == NULL) {
        DPRINT("Couldn't allocate mmap2 shellcode object\n");
        ret = ENOMEM;
        goto end;
    }
    
    memcpy((this->payload + MMAP2_LEN_OFFSET), &length, WORD_SIZE);
    memcpy((this->payload + MMAP2_PROT_OFFSET), &prot, WORD_SIZE);
    memcpy((this->payload + MMAP2_FLAGS_OFFSET), &flags, WORD_SIZE); 
    DPRINTHEX(MMAP2_STUB, sizeof(MMAP2_STUB), "OLD mmap2 shellcode len(%d) =", sizeof(MMAP2_STUB));
    DPRINTHEX(this->payload, 29, "NEW mmap2 shellcode len(%d) =", this->psize);

end:
    if (ret != 0 && this != NULL) {
        shellcode_free(&this);
    }
    DEXIT();
    return this;
}



/*
 * Creates a customized thread shellcode with the caller specified arguments
 * to clone system call and the thread payload. Note: For more detailed information on the arguments
 * refer to mmap manual page (man clone). 
 *
 * @param  tpayload    [IN] The payload(shellcode) to be executed in the thread.
 * @param  tpsize      [IN] The size of the tpayload string not including the terminating
 *                          NULL. As convention jugaad does not include/ignores the 
 *                          terminating NULL character.
 * @param  child_stack [IN] Stack bottom address in the remote process. For more
 *                          details check child_stack argument to clone(man clone)
 * @param  flags       [IN] Clone flags, specifies what is shared between the remote
 *                          process and it's child(our thread). For more details
 *                          details check flags argument to clone(man clone)
 */
struct shellcode * shellcode_thread(unsigned char * tpayload,
                                    size_t tpsize,
                                    void * child_stack,
                                    int flags)
{
    struct shellcode * this = NULL;
    int ret = 0;

    DENTER();

    if (tpayload == NULL) {
        DPRINT("No payload specified for the thread\n");
        ret = EINVAL;
        goto end;
    }
    /* 
     * Mild test for thread payload size, however practical size would be way more
     * than what is passed.
     */
    if (tpsize < 1) {
        DPRINT("Invalied thread payload size=(%d)\n", tpsize);
        ret = EINVAL;
        goto end;
    }
    if (child_stack == NULL) {
        DPRINT("No address specified for child stack\n");
        ret = EINVAL;
        goto end;
    }

    /*
     * Ignore the terminating NULL for the shellcode sizes by decrementing 1
     * Thread Shellcode composition:
     * 1. Copy the clone code.
     * 2. Append the custom thread payload.
     * 3. Append the clone tail i.e. the exit system call.
     * 4. Edit the stub values in the shellcode: child_stack and clone flags
     */
    this = shellcode_copy((unsigned char *)CLONE_STUB_HEAD, (sizeof(CLONE_STUB_HEAD) - 1));
    if (this == NULL) {
        DPRINT("Couldn't allocate CLONE_STUB_HEAD shellcode object\n");
        ret = ENOMEM;
        goto end;
    }
    ret = shellcode_append(this, tpayload, tpsize);
    if (ret != 0) {
        DPRINT("Couldn't append thread payload to clone shellcode object\n");
        ret = ENOMEM;
        goto end;
    }
    ret = shellcode_append(this, (unsigned char *)CLONE_STUB_TAIL, (sizeof(CLONE_STUB_TAIL) - 1));
    if (ret != 0) {
        DPRINT("Couldn't append CLONE_STUB_TAIL to clone shellcode object\n");
        ret = ENOMEM;
        goto end;
    }

    memcpy((this->payload + CLONE_STK_BOTTOM_OFFSET), &child_stack, WORD_SIZE);
    memcpy((this->payload + CLONE_FLAGS_OFFSET1), &flags, WORD_SIZE);
    memcpy((this->payload + CLONE_FLAGS_OFFSET2), &flags, WORD_SIZE); 

    DPRINTHEX(CLONE_STUB_HEAD, sizeof(CLONE_STUB_HEAD), "OLD CLONE_STUB_HEAD shellcode len(%d) =", sizeof(CLONE_STUB_HEAD));
    DPRINTHEX(this->payload, this->psize, "NEW CLONE_STUB_HEAD shellcode len(%d) =", this->psize);
    //DPRINTHEX(THREAD_PAYLOAD, sizeof(THREAD_PAYLOAD), "OLD THREAD_PAYLOAD shellcode len(%d) =", sizeof(THREAD_PAYLOAD));
    DPRINTHEX(CLONE_STUB_HEAD, sizeof(CLONE_STUB_TAIL), "OLD CLONE_STUB_HEAD shellcode len(%d) =", sizeof(CLONE_STUB_TAIL));
end:
    if (ret != 0 && this != NULL) {
        shellcode_free(&this);
    }
    DEXIT();

    return this;
}

/* Given the custom thread payload size, it returns the total
 * thread code size which will be injected into the remote process, 
 * includes CLONE_STUB_HEAD size, payload size and CLONE_STUB_TAIL size.
 *
 * @param  payload_size  [IN] The size of the user specified (custom) 
 *                            shellcode being used.
 *
 * @return  The total size of the thread payload which includes the 
 *          clone stub shellcode sizes and the custom shellcode.
 */
size_t shellcode_get_threadcode_size(size_t payload_size)
{
    DENTER();

    DEXIT();
    return ((sizeof(CLONE_STUB_HEAD) - 1) + payload_size + (sizeof(CLONE_STUB_TAIL) - 1));
}

