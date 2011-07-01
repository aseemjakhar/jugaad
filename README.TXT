				Jugaad Readme
				_____________


Project:      Jugaad - Thread Injection Kit
Version:      1.0
Author:       Aseem Jakhar
Organization: null - The open security community
Websites:     http://null.co.in
              http://nullcon.net
Copyright (c) 2011-2021 Aseem Jakhar <aseemjakhar_at_gmail.com>. All rights reserved.


A. Introduction
_______________

Jugaad is an attempt to create CreateRemoteThread() equivalent for *nix platform. The current version
supports only Linux operating system. For details on what is the methodology behind jugaad and how
things work under the hood visit http://null.co.in/section/projects for a detailed paper.


B. Howto
________
To use jugaad in a program all you need to do is compile the source. It creates libjugaad.a library which
you can link in your programs. You need to include jugaad.h in your code. The function that provides this
functionality is create_remote_thread() and is perhaps the only function required to be used.The header
file jugaad.h also explains the create_remote_thread() function and it's parameters in detail.


C. Compiling
____________

1. In the jugaad directory run
  a. make lib
     This will create 'libjugaad.a' in the same directory.
  b. make
     This will also create two extra binaries 'testjugaad' and 'testproc'. testjugaad is a sample program
     that uses libjugaad. testproc is a very simple program that can be used as the victim process when
     testing the functionality.
2. The Makefile defaults to creating debug version of the library which has way too many printfs'.
   If you want to compile libjugaad for production, make sure you remove the CFLAGS '-DDEBUG' and '-g'
   in the Makefile.


D. Next release
_______________

1. Add support for 64 bit systems.
2. Add support for other *nix platforms.
3. Add support for stealthy library injection.
4. Add support for remote process snooping. 


E. Contribution
_______________

Feel free to send me an email (on aseemjakhar_at_gmail.com):
1. If you would like to contribute to jugaad project.
2. If you would like to contribute to the null community in any way.

