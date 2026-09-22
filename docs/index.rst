Mhook
=====

Mhook is a Windows inline function hooking library for x86 and x64. It
redirects calls to a replacement function while preserving access to the
original through a trampoline, and hooks can be installed and removed at
runtime.

This reference documents the public interface, generated from the Doxygen
comments in ``mhook-lib/mhook.h``.

.. toctree::
   :maxdepth: 2

   api

Getting the library
--------------------

An installed package is consumed from CMake:

.. code-block:: cmake

   find_package(mhook 3.0 CONFIG REQUIRED)
   target_link_libraries(your_target PRIVATE mhook::mhook)

The public header is available as ``<mhook-lib/mhook.h>``.
