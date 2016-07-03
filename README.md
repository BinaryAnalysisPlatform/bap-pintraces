# Overview

Pin tracer - a tracer based on [Pin: Intel’s Dynamic Binary Instrumentation
Engine.](https://software.intel.com/en-us/articles/pintool) It executes a binary
executable and saves trace data using [Protocol
Buffer](https://developers.google.com/protocol-buffers/) format. The contents of
the trace data is defined in
[bap-frames](https://github.com/BinaryAnalysisPlatform/bap-frames) project.

# Preparing to build

Note: building instructions assume that you're using Ubuntu, but it
may work on other systems, that uses apt-get.

Before build tracer, you need download and install
  * [pin](https://software.intel.com/en-us/articles/pintool-downloads)
  * autoconf, libtool, protobuf-compiler, libboost-dev, libboost-filesystem-dev, libcrypto++-dev
  * [piqi library](http://piqi.org/doc/ocaml)

Here are installation example.

Download [pin](https://software.intel.com/en-us/articles/pintool-downloads) library:

```bash
$ wget http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz
```

Suppose you want install pin to $(HOME)/opt directory then:

```bash
$ tar xvzf pin-2.14-71313-gcc.4.4.7-linux.tar.gz -C $HOME/opt
```

To let Pin's makefiles know where Pin is installed, set the PIN_ROOT environment
variable with a command like:

```bash
$ export PIN_ROOT=$HOME/opt/pin-2.14-71313-gcc.4.4.7-linux
```

To let bash know where pin executable is installed add the PIN_ROOT to PATH
environment variable with a command like:

```bash
$ export PATH=$PATH:$PIN_ROOT
```

It is probably a good idea to put this command in
a startup script like .bashrc, so that you don't need to set the variable
every time you log in:

```bash
$ echo 'export PIN_ROOT=$HOME/opt/pin-2.14-71313-gcc.4.4.7-linux' >>$HOME/.bashrc
$ echo 'export PATH=$PATH:$PIN_ROOT' >>$HOME/.bashrc
```

To install apt depends, use the following command

```bash
$ sudo apt-get install autoconf libtool protobuf-compiler libprotobuf-dev libboost-filesystem-dev libcrypto++-dev 
```
To install [piqi library](http://piqi.org/doc/ocaml) with
[opam](https://opam.ocaml.org/doc/Install.html), use the following command
```bash
$ opam install piqi
```
# Build process
Download [bap-frames](https://github.com/BinaryAnalysisPlatform/bap-frames) with
following command

```bash
$ git clone https://github.com/BinaryAnalysisPlatform/bap-frames.git
```
Change folder to `bap-frames/libtrace`. Build and install library with following command
```bash
$ ./autogen.sh 
$ ./configure 
$ make
$ make install
```

Download [bap-pintraces](https://github.com/BinaryAnalysisPlatform/bap-pintraces) with following command
```bash
$ git clone https://github.com/BinaryAnalysisPlatform/bap-pintraces.git
```

Change folder to bap-pintraces and build tracer with command
```
$ make
```
To run executable `exec` and to save taint infromation to `<process id>-exec.frames`, use

```bash
$ pin -injection child -t obj-intel64/gentrace.so -o exec.frames -logall_before 1 -- exec [exec args]
```

To run executable `exec` and to save the trace data to `exec.frames`, use
```bash
$ pin -injection child -t obj-intel64/bpt.so -o exec.frames -- exec [exec args]
```
