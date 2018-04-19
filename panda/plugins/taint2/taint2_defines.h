/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
 PANDAENDCOMMENT */

#ifndef TAINT2_DEFINES_H
#define TAINT2_DEFINES_H

#define EXCEPTIONSTRING "3735928559"    // 0xDEADBEEF read from dynamic log
#define OPNAMELENGTH 15
#define FUNCNAMELENGTH 50
#define FUNCTIONFRAMES 10               // handle 10 frames for now, should be sufficient
#define MAXREGSIZE 16                   // maximum LLVM register size is 8 bytes
#define MAXFRAMESIZE 5000               // maximum number of LLVM values a function can use

// set REGS/NUM_REGS macros - maybe this should be moved elsewhere?
#include "qemu/osdep.h"
#if defined(TARGET_I386)
#define NUM_REGS CPU_NB_REGS
#define REGS(env) ((env)->regs)
#elif defined(TARGET_ARM)
#define NUM_REGS 16
#define REGS(env) ((env)->aarch64 ? (env)->xregs : (env)->regs)
#elif defined(TARGET_PPC)
#define NUM_REGS 32
#define REGS(env) ((env)->gpr)
#endif

struct ShadowState;

/**
 *  @struct taint2_state_t
 *
 *  @brief This structure encapsulates the runtime state of the taint2 plugin.
 */
typedef struct taint2_state_t {
    void *plugin;           ///< Pointer to plugin, used for manipulating callbacks.
    ShadowState *shadow;    ///< Taint memory.
    bool debug;             ///< Debug flag.
    bool tainted_pointer;
    bool track_taint_state; ///< Turns on tracking taint change across a basic block.
    bool llvm_optimize;
    bool llvm_inline;       ///< If possible, use LLVM inlining for taint operation.
    bool initialized;       ///< Whether plugin has been initialized for the fitst time.
    bool enabled;           ///< Taint propagation is enabled.
    bool enablePending;     ///< Enable taint propagation the next time this is possible.
    bool disablePending;    ///< Disable taint propagation the next time this is possible.
    bool clearOnEnable;     ///< Clear existing taint when taint propagation is re-enabled.
} taint2_state_t;
extern taint2_state_t taint2_state;

#endif
/* vim: set tabstop=4 softtabstop=4 expandtab: */
