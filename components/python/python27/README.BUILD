###########################################################
Python BUILD notes.
###########################################################

Building Python 2.7 in Pluribus environment requires a few
steps and hacks.

1) Ensure gdbm and m4 packages are installed pkg instal gdbm gnu-m4 
2) Build autoconf 2.69 in this workspace and install it, unless already installed.
3) Ensure Gcc 4.8 is present in /usr/gcc/4.8
4) Ensure that system/header/header-audio package is installed if you want ossaudiodev and sunaudiodev modules to be built.
5) cd /usr/lib/python2.6/vendor-packages/pkg/flavor and apply the following hacks

   a) cp depthlimitedmf.py depthlimitedmf27.py
   b) Edit python.py and apply the following patch:
--- /usr/lib/python2.6/vendor-packages/pkg/flavor/python.py.orig      2015-07-22 03:24:42.284681464 -0700
+++ /usr/lib/python2.6/vendor-packages/pkg/flavor/python.py   2015-07-21 23:47:54.480653890 -0700
@@ -163,6 +163,7 @@
         deps = []
         errs = []
         path_version = None
+        return deps, errs, {}
 
         dir_major = None
         dir_minor = None


