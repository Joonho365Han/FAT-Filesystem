#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "disk.h"

#define FS_INIT_KEY 1357111317

#define MAX_FIL_NAME_LEN 15
#define MAX_FIL_COUNT 64
#define MAX_FIL_DESC 32

#define FAT_FREE -2
#define FAT_EOF -1

/* --- NOTE ---
1. This library does not support threading
2. This library supports only one disk at a time
*/

/* ::: START Basic variables */
typedef struct
{
    int   opened;
    int   f_index;
    off_t file_ptr;
    int   blk_ptr;
} __fd;

typedef struct
{
    char name[MAX_FIL_NAME_LEN+1]; // 1 is for '\0'
    int  size;
    int  is_open;
    int  first_block;
} __file;

typedef struct
{
    int  key;
    int  root_block_index;
    int  root_block_count;
    int  FAT_block_index;
    int  FAT_block_count;
    int  data_block_start;
} __superblock;

__superblock *__disk_fs    = NULL; // Disk Superblock
__file       *__root_files = NULL; // List of files and their metadata
int          *__FAT_table  = NULL; // List of "next block" for FAT
__fd         *__file_table = NULL; // List of file access instances

/* --- Design of FAT blocks: ---
Each block has tags associated with it about next block.
1. The table shows which block is the next block
2. If the next block index is -1, it's the end of file.
3. If the next block index is -2, it's free.
*/

/* END Basic variables */




/* ::: START Helper functions */
int __find_file_called(char *file_name)
{
    int i;
    for (i=0; i<MAX_FIL_COUNT; i++)
        if (strcmp(__root_files[i].name,file_name) == 0)
            return i;
    return -1;
}

int __get_free_fd()
{
    int i;
    for (i=0; i<MAX_FIL_DESC; i++)
        if (!__file_table[i].opened)
            return i;
    return -1;
}

int __get_free_block()
{
    int i, number_of_data_blocks = __disk_fs->FAT_block_count/sizeof(int);
    for (i=0; i<number_of_data_blocks; i++)
        if (__FAT_table[i] == FAT_FREE)
            return i;
    return -1;
}

int __descriptor_is_invalid(int fd)
{
    if (__disk_fs == NULL)
        return -1;
    if (fd < 0 || fd >= MAX_FIL_DESC)
        return -1;
    if (!__file_table[fd].opened)
        return -1;

    return 0;
}

int __change_file_size(int fd, off_t new_len)
{
    //  Current file info
    __file *file           = &__root_files[__file_table[fd].f_index];
    int     curr_first_blk = file->first_block;
    int    *curr_file_size = &file->size;
    off_t  *curr_file_ptr  = &__file_table[fd].file_ptr;
    int    *curr_blk_ptr   = &__file_table[fd].blk_ptr;

    int blks_involved = (((*curr_file_size > new_len) ? *curr_file_size : new_len) - 1)/BLOCK_SIZE + 1;
    int FAT_unchanged = (((*curr_file_size < new_len) ? *curr_file_size : new_len) - 1)/BLOCK_SIZE;
    //  ----- What are these? -----
    //  If file is extended, add blocks including and after FAT_unchanged and mark last block as EOF.
    //  If file is shrunk, free blocks after FAT_unchanged and mark FAT_unchanged'th FAT as EOF

    int i, curr_block = curr_first_blk;
    for (i=0; i<blks_involved && curr_block>0; i++)
    {
        if (*curr_file_size < new_len)  // Extended
        {
            if (i == blks_involved-1)
                __FAT_table[curr_block] = FAT_EOF;
            else if (i >= FAT_unchanged)
                __FAT_table[curr_block] = __get_free_block();

            curr_block = __FAT_table[curr_block];
        }
        else  // Shrunk
        {
            int curr = curr_block;
            curr_block = __FAT_table[curr_block];

            if (i == FAT_unchanged)
                __FAT_table[curr] = FAT_EOF;
            else if (i > FAT_unchanged)
                __FAT_table[curr] = FAT_FREE;
        }
    }

    /*
    You could run out of space while increasing size.
    In this case, simply stop increasing and return.
    */
    if (i < blks_involved)
        *curr_file_size = i * BLOCK_SIZE;
    else
        *curr_file_size = new_len;
    *curr_file_ptr = (*curr_file_ptr<*curr_file_size) ? *curr_file_ptr : *curr_file_size;
    *curr_blk_ptr  = curr_first_blk;
    for (i=0; i<(*curr_file_ptr)/BLOCK_SIZE; i++)
        *curr_blk_ptr = __FAT_table[*curr_blk_ptr];

    return 0;
}
/* END Helper functions */




/* ::: START Mount Calls */
int make_fs(char *disk_name)
{
    /* START Error check */
    if (make_disk(disk_name)) 
        return -1;
    if (open_disk(disk_name)) 
        return -1;
    /* END Error check */

    __superblock fs;
    fs.key = FS_INIT_KEY;
    fs.root_block_index = 1;
    fs.root_block_count = 1 + (sizeof(__file)*MAX_FIL_COUNT - 1)/BLOCK_SIZE;
    fs.FAT_block_index = fs.root_block_index + fs.root_block_count;
    fs.FAT_block_count = (DISK_BLOCKS - 1 - fs.root_block_count) / (1 + BLOCK_SIZE/sizeof(int));
    fs.data_block_start = fs.FAT_block_index + fs.FAT_block_count;

    // Write superblock to disk
    char buf[BLOCK_SIZE];  
    memcpy(buf, &fs, sizeof(__superblock));
    if (block_write(0, buf)) return -1;

    if (close_disk()) return -1;
    return 0;
}

int mount_fs(char *disk_name)
{
    /* START Error check */
    if (__disk_fs != NULL) 
        return -1;
    if (open_disk(disk_name)) 
        return -1;

    //  Superblock validity
    __disk_fs = (__superblock*) malloc(sizeof(BLOCK_SIZE));
    if (block_read(0, (char*) __disk_fs))
        return -1;
    if (__disk_fs->key != FS_INIT_KEY)
    {
        free(__disk_fs);
        __disk_fs = NULL;
        return -1;
    }
    /* END Error check */

    // Load __root_files
    int i;
    int blocks_to_copy = __disk_fs->root_block_count;
    int starting_block = __disk_fs->root_block_index;
    __root_files = (__file*) malloc(blocks_to_copy*BLOCK_SIZE);
    for (i=0; i<blocks_to_copy; i++)
        if (block_read(starting_block + i, (char*) (__root_files + i*BLOCK_SIZE)))
        {
            free(__disk_fs);
            free(__root_files);
            __disk_fs = NULL;
            return -1;
        }

    // Load __FAT_table
    blocks_to_copy = __disk_fs->FAT_block_count;
    starting_block = __disk_fs->FAT_block_index;
    __FAT_table = (int*) malloc(blocks_to_copy*BLOCK_SIZE);
    for (i=0; i<blocks_to_copy; i++)
        if (block_read(starting_block + i, (char*) (__FAT_table + i*BLOCK_SIZE)))
        {
            free(__disk_fs);
            free(__root_files);
            free(__FAT_table);
            __disk_fs = NULL;
            return -1;
        }

    // Init file descriptors
    __file_table = (__fd*) malloc(sizeof(__fd)*MAX_FIL_DESC);
    for (i=0; i<MAX_FIL_DESC; i++)
        __file_table[i].opened = 0;

    return 0;
}

int umount_fs(char *disk_name)
{
    /* START Error check */
    if (__disk_fs == NULL) 
        return -1;
    if (__disk_fs->key != FS_INIT_KEY) 
        return -1;
    int i;
    for (i=0; i<MAX_FIL_DESC; i++)
        if (__file_table[i].opened)
            return -1;
    /* END Error check */

    // Save superblock
    if (block_write(0, (char*) __disk_fs))
        return -1;

    // Save __root_files
    int blocks_to_copy = __disk_fs->root_block_count;
    int starting_block = __disk_fs->root_block_index;
    for (i=0; i<blocks_to_copy; i++) 
        if (block_write(starting_block + i, (char*) (__root_files + i*BLOCK_SIZE)))
            return -1;

    // Save __FAT_table
    blocks_to_copy = __disk_fs->FAT_block_count;
    starting_block = __disk_fs->FAT_block_index;
    for (i=0; i<blocks_to_copy; i++)
        if (block_write(starting_block + i, (char*) (__root_files + i*BLOCK_SIZE)))
            return -1;

    free(__disk_fs);
    free(__root_files);
    free(__FAT_table);
    free(__file_table);
    __disk_fs = NULL;

    if (close_disk()) return -1;
    return 0;
}
/* END Mount calls */




/* ::: START File I/O API */
int fs_open(char *file_name)
{
    /* START Error check */
    if (__disk_fs == NULL)
        return -1;
    int f_index = __find_file_called(file_name);
    if (f_index < 0)
        return -1;
    int free_fd = __get_free_fd();
    if (free_fd < 0)
        return -1;
    /* END Error check */

    __root_files[f_index].is_open++; //increase references to file
    __file_table[free_fd].opened = 1;
    __file_table[free_fd].f_index = f_index;
    __file_table[free_fd].file_ptr = 0;
    __file_table[free_fd].blk_ptr = 0;

    return free_fd;
}

int fs_close(int fd)
{
    /* Error check */
    if (__descriptor_is_invalid(fd))
        return -1;

    __root_files[__file_table[fd].f_index].is_open--;
    __file_table[fd].opened = 0;

    return 0;
}

int fs_create(char *file_name)
{
    /* START Error check */
    if (__disk_fs == NULL) 
        return -1;
    if (strlen(file_name) > MAX_FIL_NAME_LEN)
        return -1;
    if (__find_file_called(file_name) >= 0)
        return -1;

    int f_index = 0;
    for (; f_index<MAX_FIL_COUNT; f_index++)
        if (__root_files[f_index].name[0] != '\0')
            break;

    if (f_index == MAX_FIL_COUNT)
        return -1;
    int free_fd = __get_free_fd();
    if (free_fd < 0)
        return -1;
    int free_block = __get_free_block();
    if (free_block < 0)
        return -1;
    /* END Error check */

    strncpy(__root_files[f_index].name, file_name, MAX_FIL_NAME_LEN);
    __root_files[f_index].size = 0;
    __root_files[f_index].is_open = 1;
    __root_files[f_index].first_block = free_block;

    __FAT_table[free_block] = FAT_EOF;

    __file_table[free_fd].opened = 1;
    __file_table[free_fd].f_index = f_index;
    __file_table[free_fd].file_ptr = 0;
    __file_table[free_fd].blk_ptr = 0;

    return 0;
}

int fs_delete(char *file_name)
{
    /* START Error check */
    if (__disk_fs == NULL) 
        return -1;
    int f_index = __find_file_called(file_name);
    if (f_index < 0)
        return -1;
    if (__root_files[f_index].is_open)
        return -1;
    /* END Error check */

    __root_files[f_index].name[0] = '\0';
    int file_block = __root_files[f_index].first_block;
    while (__FAT_table[file_block] > 0)
    {
        int block_to_free = file_block;
        file_block = __FAT_table[block_to_free];
        __FAT_table[block_to_free] = FAT_FREE;
    }

    return 0;
}

int fs_listfiles(char ***files)
{
    /* Error check */
    if (__disk_fs == NULL) 
        return -1;

    *files = (char**) malloc(sizeof(char*)*(MAX_FIL_COUNT+1));
    int i, skip_count=0;
    for (i=0; i+skip_count<MAX_FIL_COUNT; i++)
        if (__root_files[i-- + skip_count++].name[0] != '\0')
        {
            (*files)[++i] = (char*) malloc(MAX_FIL_NAME_LEN+1);
            strncpy((*files)[i], __root_files[i + --skip_count].name, MAX_FIL_NAME_LEN+1);
        }
    (*files)[i] = NULL;

    return 0;
}

int fs_get_filesize(int fd)
{
    /* Error check */
    if (__descriptor_is_invalid(fd))
        return -1;

    return __root_files[__file_table[fd].f_index].size;
}

int fs_lseek(int fd, off_t offset)
{
    /* START Error check */
    int filesize = fs_get_filesize(fd); // Handles some errors
    if (filesize < 0)
        return -1;
    if (offset < 0 || offset > filesize)
        return -1;
    /* END Error check */

    __file_table[fd].file_ptr = offset;
    __file_table[fd].blk_ptr = __root_files[__file_table[fd].f_index].first_block;
    int i;
    for (i=0; i<offset/BLOCK_SIZE; i++)
        __file_table[fd].blk_ptr = __FAT_table[__file_table[fd].blk_ptr];

    return 0;
}

int fs_truncate(int fd, off_t length)
{
    /* START Error check */
    if (__descriptor_is_invalid(fd))
        return -1;
    if(length < 0 || length > __root_files[__file_table[fd].f_index].size)
        return -1;
    /* END Error check */

    return __change_file_size(fd, length);
}

int fs_rdwr(int fd, void *buf, size_t nbyte, int write_mode)
{
    /* START Error check */
    if (__descriptor_is_invalid(fd))
        return -1;
    if (buf == NULL || nbyte < 0)
        return -1;
    /* END Error check */

    off_t  *file_ptr = &__file_table[fd].file_ptr;
    int    *blk_ptr  = &__file_table[fd].blk_ptr;
    int    filesize  = __root_files[__file_table[fd].f_index].size;
    int    oldsize   = filesize;

    //  Increase size if file pointer writes beyond size
    if (write_mode && *file_ptr+nbyte > filesize)
    {
        __change_file_size(fd, *file_ptr+nbyte);
        filesize = __root_files[__file_table[fd].f_index].size;
    }

    //  File I/O
    int block_offset = *file_ptr % BLOCK_SIZE;
    int buf_offset   = 0;
    int total_copied = 0;
    while (*file_ptr<filesize && nbyte)
    {
        //  Load block
        char block[BLOCK_SIZE];
        if (block_read(*blk_ptr, block))
        {
            //  Load failed. Shrink file and return the result so far.
            if (filesize > oldsize)
                __change_file_size(fd, ((*file_ptr > oldsize) ? *file_ptr : oldsize));
            return total_copied;
        }

        //  Copy data to/from this block
        int rest_of_block = BLOCK_SIZE - block_offset;
        int bytes_to_copy, copied = 0;
        bytes_to_copy = (nbyte < filesize - *file_ptr) ? nbyte : filesize - *file_ptr;
        bytes_to_copy = (bytes_to_copy < rest_of_block) ? bytes_to_copy : rest_of_block;
        while (copied < bytes_to_copy)
        {
            if (write_mode)
                block[block_offset + copied++] = *((char*)(buf + buf_offset++));
            else
                *((char*)(buf + buf_offset++)) = block[block_offset + copied++];
        }

        //  Write back if in write mode 
        if (write_mode)
            if (block_write(*blk_ptr, block))
            {   
                //  Write back failed. Shrink file and return the result so far.
                if (filesize > oldsize)
                    __change_file_size(fd, ((*file_ptr > oldsize) ? *file_ptr : oldsize));
                return total_copied;
            }
        if (copied == BLOCK_SIZE)
            *blk_ptr = __FAT_table[*blk_ptr];

        total_copied += copied;
        (*file_ptr)  += copied;
        nbyte        -= copied;
        block_offset  = 0;
    }

    return total_copied;
}

int fs_read(int fd, void *buf, size_t nbyte)
{
    return fs_rdwr(fd, buf, nbyte, 0);
}

int fs_write(int fd, void *buf, size_t nbyte)
{
    return fs_rdwr(fd, buf, nbyte, 1);
}
/* END File I/O API */