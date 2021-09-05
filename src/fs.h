#pragma once

#include "arch.h"

enum { MG_FS_READ = 1, MG_FS_WRITE = 2, MG_FS_DIR = 4 };

// Filesystem API functions
struct mg_fs {
  // Return real path (i.e. with resolved symlinks etc)
  char *(*realpath)(const char *path, char *resolved_path);
  
  // Return file size and modification time   
  int (*stat)(const char *path, size_t *size, time_t *mtime);

  // Enumerates objects in directory
  void (*list)(const char *path, void (*fn)(const char *, void *), void *);
  
  // Open file
  struct mg_fd *(*open)(const char *path, int flags);
  
  // Close file
  void (*close)(struct mg_fd *fd);
  
  // Read file
  size_t (*read)(void *fd, void *buf, size_t len);
  
  // Write file
  size_t (*write)(void *fd, const void *buf, size_t len);
  
  // Seek file
  size_t (*seek)(void *fd, size_t offset);
};

// File descriptor
struct mg_fd {
  void *fd;
  struct mg_fs *fs;
};

extern struct mg_fs mg_fs_posix;   // POSIX open/close/read/write/seek
extern struct mg_fs mg_fs_packed;  // Packed FS, see examples/complete
