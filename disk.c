#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "disk.h"

// NOTE THAT THIS LIBRARY WILL NOT SUPPORT MULTIPLE DISKS AT ONCE

/******************************************************************************/
static int active = 0;  /* is the virtual disk open (active) */
static int handle;      /* file handle to A SINGLE virtual disk       */

/******************************************************************************/
int make_disk(char *name)
{ 
    /*
    Basically zeroes the disk of "name". That's it.
    returns status.
    */

  int f, cnt;
  char buf[BLOCK_SIZE];

  if (!name) { // null pointer
    fprintf(stderr, "make_disk: invalid file name\n");
    return -1;
  }

  if ((f = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) { // opend the "virtual disk" file
    perror("make_disk: cannot open file");
    return -1;
  }

  memset(buf, 0, BLOCK_SIZE); // creates empty memory
  for (cnt = 0; cnt < DISK_BLOCKS; ++cnt) // DISK_BLOCKS is an expected global variable. In disk.h
    write(f, buf, BLOCK_SIZE); // ZEROS THE DISK file

  close(f); // saves zeroed file to disk

  return 0;
}

int open_disk(char *name)
{
    /*
    opens the disk of name "name" but DOES NOT MOUNT THE FS. THERE'S A DIFFERENCE.
    returns status
    */
  int f;

  if (!name) { // wrong name | no name of disk to open
    fprintf(stderr, "open_disk: invalid file name\n");
    return -1;
  }  
  
  if (active) { // The "active" variable indicates if this "driver" library is active
    fprintf(stderr, "open_disk: disk is already open\n");
    return -1;
  }
  
  if ((f = open(name, O_RDWR, 0644)) < 0) { // open disk file
    perror("open_disk: cannot open file");
    return -1;
  }

  handle = f; // THE SPECIFIC FD TO USE FOR THE VIRTUAL DISK. NOTE THIS. REMEMBER HOW IT'S A GLOBAL VARIABLE
  active = 1;

  return 0;
}

int close_disk()
{
    /* 
    Closes the disk file. 
    IN UNIX EVERYTHING IS A FILE. SO IT's IMPORTANT TO NOTE THAT OPENING A DISK IS NOT OPENING THE FILESYSTEM. 
    returns status
    */
  if (!active) {
    fprintf(stderr, "close_disk: no open disk\n");
    return -1;
  }
  
  close(handle);

  active = handle = 0;

  return 0;
}

int block_write(int block, char *buf) // block = index of block in disk. but = address to copy from
{
    /*
    writes to disk index "block" just ONE block from buf
    returns status
    */
  if (!active) { // disk is not open
    fprintf(stderr, "block_write: disk not active\n");
    return -1;
  }

  if ((block < 0) || (block >= DISK_BLOCKS)) { // block index out of bounds
    fprintf(stderr, "block_write: block index out of bounds\n");
    return -1;
  }

  if (lseek(handle, block * BLOCK_SIZE, SEEK_SET) < 0) { 
  // lseek is a filesystem function, but since our "disk" is also a file, lseek in this case is basically the same ting as a DEVICE DRIVER
    perror("block_write: failed to lseek");
    return -1;
  }

  if (write(handle, buf, BLOCK_SIZE) < 0) {
    perror("block_write: failed to write");
    return -1;
  }

  return 0;
}

int block_read(int block, char *buf)
{
    /*
    reads from disk index "block" just ONE block into buf
    returns status
    */
  if (!active) {
    fprintf(stderr, "block_read: disk not active\n");
    return -1;
  }

  if ((block < 0) || (block >= DISK_BLOCKS)) {
    fprintf(stderr, "block_read: block index out of bounds\n");
    return -1;
  }

  if (lseek(handle, block * BLOCK_SIZE, SEEK_SET) < 0) {
    perror("block_read: failed to lseek");
    return -1;
  }

  if (read(handle, buf, BLOCK_SIZE) < 0) {
    perror("block_read: failed to read");
    return -1;
  }

  return 0;
}
