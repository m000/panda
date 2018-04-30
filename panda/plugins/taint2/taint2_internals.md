# taint2 internals

This is an attempt to document the internals of taint2 plugin.
The documentation was written while implementing support for temporarily
disabling taint propagation. This required a fair amount of refactoring.

Because of this, the main focus is on what is happening inside taint2.cpp.

## taint2.cpp

### init\_plugin()

Here, there are only initializations that need to be executed at PANDA
startup.

  * panda\_enable\_memcb(): Enables callbacks for memory reads/writes.
    These are off by default in PANDA (high overhead) but are required
    in order update the taint shadow memory.
    The callbacks are registered by taint2\_enable\_taint().
  * panda\_disable\_tb\_chaining(): Disables basic block chaining.
    In principle, this allows running block-based callbacks at finer
    intervals.
  * PANDA\_CB\_GUEST\_HYPERCALL:guest\_hypercall\_callback():
    Optional. Allows program from within the VM to communicate
    with the plugin. Obviously, this is only possible when the
    plugin is run in inline mode, and not on a replay.

**XXX:**
  * Perhaps panda\_enable\_memcb() could be pushed to taint2\_enable\_taint().
  * Not sure why we need panda\_disable\_tb\_chaining(). Check the PIRATE paper for this.
  * Document why we need callstack\_instr plugin, also initialized here.

### taint2\_enable\_taint()

Here, the true initialization of the plugin happens. E.g. shadow memory is
allocated, LLVM is initialized, memory and other callbacks are registered or
enabled.

  * Initializes taint2\_state.shadow, if needed.
    This must happen before LLVM initialization because the shadow map is used
    to initialize the taint function pass.
  * Initializes LLVM stuff via \_\_taint2\_initialize(), if needed.
  * PANDA\_CB\_BEFORE\_BLOCK\_EXEC\_INVALIDATE\_OPT:before\_block\_exec\_invalidate\_opt():
    This callback is used to determine whether the basic block which is about
    to be executed has to be retranslated. This is a simple check for a pointer
    (checks `tb->llvm_tc_ptr` - see panda/docs/manual.md, include/exec/exec-all.h).
  * PANDA\_CB\_PHYS\_MEM\_BEFORE\_READ:phys\_mem\_read\_callback():
    Pushes address to memlog.
  * PANDA\_CB\_PHYS\_MEM\_BEFORE\_WRITE:phys\_mem\_write\_callback():
    Pushes address to memlog. Same code as previous.
  * PANDA\_CB\_AFTER\_BLOCK\_EXEC:after\_block\_exec():
    This is a hook for actions that have to be postponed until after the end
    of the executing block. This includes actually disabling taint analysis.
  * PANDA\_CB\_ASID\_CHANGED:asid\_changed\_callback():
    Only used for debugging. Changes log level if the new ASID matches `debug_asid`.

### \_\_taint2\_initialize()

  * memlog? what is it?
  * panda\_enable\_llvm():
  * panda\_enable\_llvm\_helpers():
  * Also, adds a new function pass to the FPM of tcg\_llvm\_ctx.
    Can this pass be removed to disable taint propagation?


<!-- Use this in vim to escape underscores:
s/\([^\\]\)\_/\1\\_/g
-->
