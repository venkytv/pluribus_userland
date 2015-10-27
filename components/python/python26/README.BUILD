###########################################################
Python BUILD notes.
###########################################################

Building Python 2.7 in Pluribus environment requires a few
steps and hacks.

Please read components/python/python27/README.BUILD first. Those steps are necessary.
Additionally the readline module fails to link correctly and has to be built by hand
at this time.

Steps:

1) Build normally: ./build.sh python/python26
2) The build will fail during packaging complaining about readline.so missing.
3) Now do the following:

cd /path/to/oi-userland/components/python/python26/build/i86
/usr/gcc/4.8/bin/gcc -m32 -O3 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 -D_XPG6 -std=c99 -fPIC -DPIC -fno-strict-aliasing -m32 -O3 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 -D_XPG6 -std=c99 -DNDEBUG -g -O3 -Wall -Wstrict-prototypes -I. -I/path/to/oi-userland/components/python/python26/Python-2.6.9/./Include -I. -IInclude -IPython -I/usr/include/ncurses -I/usr/lib/libffi-3.0.8/include -I/path/to/oi-userland/components/python/python26/Python-2.6.9/Include -I/path/to/oi-userland/components/python/python26/build/i86 -c /path/to/oi-userland/components/python/python26/Python-2.6.9/Modules/readline.c -o build/temp.solaris-2.11-i86pc-2.6/path/to/oi-userland/components/python/python26/Python-2.6.9/Modules/readline.o

/usr/gcc/4.8/bin/gcc -m32 -O3 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 -D_XPG6 -std=c99 -shared -m32 -R/usr/gcc/4.8/lib -L/usr/gcc/4.8/lib -R/usr/gnu/lib -L/usr/gnu/lib -lncurses build/temp.solaris-2.11-i86pc-2.6path/to//oi-userland/components/python/python26/Python-2.6.9/Modules/readline.o -L/usr/lib/termcap -L/usr/gcc/4.8/lib -L/usr/gnu/lib -L. -Wl,-R/usr/gcc/4.8/lib -Wl,-R/usr/gnu/lib -lpython2.6 -o build/lib.solaris-2.11-i86pc-2.6/readline.so -lreadline

cd /path/to/oi-userland/components/python/python26/build/amd64
/usr/gcc/4.8/bin/gcc -m64 -O3 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 -D_XPG6 -std=c99 -fPIC -DPIC -fno-strict-aliasing -m64 -O3 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 -D_XPG6 -std=c99 -DNDEBUG -g -O3 -Wall -Wstrict-prototypes -I. -I/path/to/oi-userland/components/python/python26/Python-2.6.9/./Include -I. -IInclude -IPython -I/usr/include/ncurses -I/usr/lib/libffi-3.0.8/include -I/path/to/oi-userland/components/python/python26/Python-2.6.9/Include -I/path/to/oi-userland/components/python/python26/build/amd64 -c /path/to/oi-userland/components/python/python26/Python-2.6.9/Modules/readline.c -o build/temp.solaris-2.11-i86pc-2.6/path/to/oi-userland/components/python/python26/Python-2.6.9/Modules/readline.o

/usr/gcc/4.8/bin/gcc -m64 -O3 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 -D_XPG6 -std=c99 -shared -m64 -R/usr/gcc/4.8/lib/amd64 -L/usr/gcc/4.8/lib/amd64 -R/usr/gnu/lib/amd64 -L/usr/gnu/lib/amd64 -lncurses build/temp.solaris-2.11-i86pc-2.6/path/to/oi-userland/components/python/python26/Python-2.6.9/Modules/readline.o -L/usr/lib/termcap -L/usr/gcc/4.8/lib/amd64 -L/usr/gnu/lib/amd64 -L. -Wl,-R/usr/gcc/4.8/lib/amd64 -Wl,-R/usr/gnu/lib/amd64 -lpython2.6 -o build/lib.solaris-2.11-i86pc-2.6/64/readline.so -lreadline

cd /path/to/oi-userland/components/python/python26/build/
cp i86/build/lib.solaris-2.11-i86pc-2.6/readline.so prototype/i386/usr/lib/python2.6/lib-dynload/
cp amd64/build/lib.solaris-2.11-i86pc-2.6/64/readline.so prototype/i386/usr/lib/python2.6/lib-dynload/64/

4) Finally rerun the build. This time it wil not go through full build since it is already done.
   It will simply jump to generating the packages again:
   ./build.sh python/python26

5) Note: This build does not include sunaudiodev and ossaudiodev modules. They are commented in the p5m file.
   If you install the corret header (as per python27/README.BUILD) and build then you can uncomment those
   lines in the p5m file.

