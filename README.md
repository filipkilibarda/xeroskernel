Welcome! If you're here, it's likely because you read my resume where I advertised this. 

This project builds on top of an extremely old version of the Linux Kernel with tons of missing functionality. If you look at [bootsec.S](/boot/boot/bootsec.S) you'll actually see `Copyright (C) 1991, 1992 Linus Torvalds`, and lots of his comments throughout the assembly code! :)

Below is a summarized/annotated diff showing which files my awesome teammate **wjwalcher** and I implemented for this project.

```diff
Create a new process (setup stack, allocate PCB)
c/create.c       |  226 ++++++++++++------

Context Switching (Kernel <-> Userland)
c/ctsw.c         |  211 ++++++++--------

Device Independent Driver Layer
c/di_calls.c     |  165 +++++++++++++

Process Scheduling / System Calling Handler
c/disp.c         | 1048 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++------------------

Kernel Boot!
c/init.c         |  107 ++++-----

Keyboard Driver
c/kbd.c          |  683 ++++++++++++++++++++++++++++++++++++++++++++++++++++

Kernel Memory Allocator
c/mem.c          |  649 ++++++++++++++++++++++++++++++++++++++++++++-----

Inter-Process Communication
c/msg.c          |  483 ++++++++++++++++++++++++++++++++++++-

Signalling - Kernel-side 
c/signal.c       |  690 ++++++++++++++++++++++++++++++++++++++++++++++++++++-

Manage Sleeping Processes
c/sleep.c        |  382 +++++++++++++++++++++--------

System Calls - Userland
c/syscall.c      |  336 ++++++++++++++++++++++----

Some userland code to demo functionality
c/user.c         |  666 ++++++++++++++++++++++++++++++++++++---------------

Header files
h/i386.h         |    1 +
h/kbd.h          |   48 ++++
h/test.h         |  161 +++++++++++++
h/xeroskernel.h  |  410 +++++++++++++++++++++----------
```

<include diff from the first commit>
<explain which stuff is yours and which is William's>

As you can see from this horrific screenshot, I have about **36 hours STRAIGHT of commits**. *Yeah, I didn't sleep*. This is what it's like meeting deadlines when I have 4 upper level engineering/machine learning courses. The code quality may be a reflection of this. You've been warned.

![Commit Horror](/commit_horror.png)


# Original README


This directory contains the source code for the Xeros operating system
which is a desicated version of the Xinu OS.

To build a Xeros image, type make in this directory. If you want to
launch bochs immediately after the make completes (assuming it is
successful) type "make beros" instead. This command will first build a
Xeros image and then start the bochs emulator.  (You can also go to
the c directory, where the source code you are editing resides, and
run the same make commands there.)

When you run "make", or "make xeros", the first two steps below are
performed. If you run "make beros" then all 3 steps are done.

1. Change to the compile directory and run make

2. If step 1 succeeds, a boot image is built by changing to the boot
directory and running make there. 

3) If step 3 succeeds, bochs is run.

If you simply type make you can, assuming there was a clean make, run
the resulting image by executing the bochs command in this directory
(i.e.  nice bochs)

Once bochs is running, choose option 6 to start the simulation and to
load and run the created image.
