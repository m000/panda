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

/*
 * PANDA taint analysis plugin
 * Ryan Whelan, Tim Leek, Sam Coe, Nathan VanBenschoten
 */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <iostream>

#include "panda/plugin.h"
#include "panda/tcg-llvm.h"

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "llvm_taint_lib.h"
#include "fast_shad.h"
#include "taint_ops.h"
#include "taint2.h"
#include "label_set.h"
#include "taint_api.h"
#include "taint2_hypercalls.h"

extern "C" {
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

// plugin initialization - destruction
bool init_plugin(void *);
void uninit_plugin(void *);

// callbacks registered by the plugin
bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb);
int phys_mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int phys_mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int asid_changed_callback(CPUState *env, target_ulong oldval, target_ulong newval);
int after_block_exec(CPUState *cpu, TranslationBlock *tb);

// callbacks offered by the plugin
void taint_state_changed(FastShad *, uint64_t, uint64_t);
PPP_PROT_REG_CB(on_taint_change);
PPP_CB_BOILERPLATE(on_taint_change);
}

// function type for functions modifying callback registration
typedef void(* panda_callback_modify_t)(void *plugin, panda_cb_type type, panda_cb cb);

// Global shadow memory
ShadowState *shadow = nullptr;

// Pointer passed in init_plugin()
void *taint2_plugin = nullptr;

// Our pass manager to derive taint ops
llvm::FunctionPassManager *FPM = nullptr;

// Taint function pass.
llvm::PandaTaintFunctionPass *PTFP = nullptr;

// For now, taint becomes enabled when a label operation first occurs, and
// becomes disabled when a query operation subsequently occurs
bool taintEnabled = false;

// taint disabling and clearing has to be deferred to the end of the executing block
bool taintJustDisabled = false;
bool taintClearOnDisable = false;

// Lets us know whether initialization has completed once.
bool taintInitialized = false;

// Taint memlog
static taint2_memlog taint_memlog;

// Configuration
bool tainted_pointer = true;
bool optimize_llvm = true;
extern bool inline_taint;
bool debug_taint = false;

/*
 * These memory callbacks are only for whole-system mode.  User-mode memory
 * accesses are captured by IR instrumentation.
 */
int phys_mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    taint_memlog_push(&taint_memlog, addr);
    return 0;
}

int phys_mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size) {
    taint_memlog_push(&taint_memlog, addr);
    return 0;
}

void taint2_enable_tainted_pointer(void) {
    tainted_pointer = true;
}

void taint2_disable_tainted_pointer(void) {
    tainted_pointer = false;
}

/**
 * @brief Enables taint propagation. Existing taint is discarded, unless
 * `clear_taint` is provided and set to `false`.
 *
 * @note Calling this function early (e.g. from the `init_plugin()`) function
 * of your plugin will result to a segfault. The earliest point you can use
 * this api call is the `after_machine_init` callback.
 */
void taint2_enable_taint(bool clear_taint) {
    if(taintEnabled) {return;}
    std::cerr << PANDA_MSG << __FUNCTION__ << "@" << rr_get_guest_instr_count() << std::endl;
    panda_cb pcb;

    // initialize/clear shadow memory
    if (clear_taint && shadow) {
        delete shadow;
        shadow = nullptr;
    }
    if (!shadow) {
        shadow = new ShadowState();
    }

    // callbacks have to be either registered or just enabled
    panda_callback_modify_t cb_modify = (!taintInitialized) ? panda_register_callback : panda_enable_callback;

    pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    cb_modify(taint2_plugin, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    pcb.phys_mem_before_read = phys_mem_read_callback;
    cb_modify(taint2_plugin, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);

    pcb.phys_mem_before_write = phys_mem_write_callback;
    cb_modify(taint2_plugin, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);

    pcb.asid_changed = asid_changed_callback;
    cb_modify(taint2_plugin, PANDA_CB_ASID_CHANGED, pcb);

    pcb.after_block_exec = after_block_exec;
    cb_modify(taint2_plugin, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    // before_block_exec requires precise_pc for panda_current_asid
    panda_enable_precise_pc();

    if (!execute_llvm) { panda_enable_llvm(); }

    if (!taintInitialized) {
        // One time initializations.
        std::string err;

        memset(&taint_memlog, 0, sizeof(taint_memlog));
        panda_enable_llvm_helpers();

        llvm::Module *mod = tcg_llvm_ctx->getModule();
        FPM = tcg_llvm_ctx->getFunctionPassManager();

        if (optimize_llvm) {
            llvm::PassManagerBuilder Builder;
            Builder.OptLevel = 2;
            Builder.SizeLevel = 0;
            Builder.populateFunctionPassManager(*FPM);
        }

        // Add the taint analysis pass to our taint pass manager.
        PTFP = new llvm::PandaTaintFunctionPass(shadow, &taint_memlog);
        FPM->add(PTFP);
        if (FPM->doInitialization()) {
            std::cout << PANDA_MSG "Done initializing taint transformation." << std::endl;
        }

        // Populate module with helper function taint ops.
        for (auto i = mod->begin(); i != mod->end(); i++){
            if (!i->isDeclaration()) PTFP->runOnFunction(*i);
        }
        std::cerr << PANDA_MSG "Done processing helper functions for taint." << std::endl;

        // Verifying llvm module.
        if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
            std::cerr << PANDA_MSG << err << std::endl;
            exit(1);
        }
        std::cerr << PANDA_MSG "Done verifying LLVM module." << std::endl;
#ifdef TAINT2_DEBUG
        tcg_llvm_write_module(tcg_llvm_ctx, "/tmp/llvm-mod.bc");
#endif
    }

    taintInitialized = true;
    taintEnabled = true;
}

void taint2_disable_taint(bool clear_taint) {
    if(!taintEnabled) {return;}
    std::cerr << PANDA_MSG << __FUNCTION__ << "@" << rr_get_guest_instr_count() << std::endl;
    taintEnabled = false;

    // actually disabling taint has to be deferred to the end of the block
    taintJustDisabled = true;
    taintClearOnDisable = clear_taint;
}

// Execute taint ops
int after_block_exec(CPUState *cpu, TranslationBlock *tb) {
    if (taintJustDisabled){
        std::cerr << PANDA_MSG << __FUNCTION__ << "@" << rr_get_guest_instr_count() << std::endl;
        taintJustDisabled = false;
        execute_llvm = 0;
        generate_llvm = 0;
        panda_do_flush_tb();
        panda_disable_memcb();

        panda_cb pcb;
        pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
        panda_disable_callback(taint2_plugin, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
        pcb.phys_mem_before_read = phys_mem_read_callback;
        panda_disable_callback(taint2_plugin, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);
        pcb.phys_mem_before_write = phys_mem_write_callback;
        panda_disable_callback(taint2_plugin, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);
        pcb.asid_changed = asid_changed_callback;
        panda_disable_callback(taint2_plugin, PANDA_CB_ASID_CHANGED, pcb);
        pcb.after_block_exec = after_block_exec;
        panda_disable_callback(taint2_plugin, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

        if (taintClearOnDisable && shadow) {
            delete shadow;
            shadow = nullptr;
        }

        //???panda_disable_precise_pc();
        //???if (execute_llvm) { panda_disable_llvm(); }
    }
    return 0;
}

/**
 * @brief Wrapper for running the registered `on_taint_change` PPP callbacks.
 * Called by the shadow memory implementation whenever changes occur to it.
 */
void taint_state_changed(FastShad *fast_shad, uint64_t shad_addr, uint64_t size) {
    Addr addr;
    if (fast_shad == &shadow->llv) {
        addr = make_laddr(shad_addr / MAXREGSIZE, shad_addr % MAXREGSIZE);
    } else if (fast_shad == &shadow->ram) {
        addr = make_maddr(shad_addr);
    } else if (fast_shad == &shadow->grv) {
        addr = make_greg(shad_addr / sizeof(target_ulong), shad_addr % sizeof(target_ulong));
    } else if (fast_shad == &shadow->gsv) {
        addr.typ = GSPEC;
        addr.val.gs = shad_addr;
        addr.off = 0;
        addr.flag = (AddrFlag)0;
    } else if (fast_shad == &shadow->ret) {
        addr.typ = RET;
        addr.val.ret = 0;
        addr.off = shad_addr;
        addr.flag = (AddrFlag)0;
    } else return;

    PPP_RUN_CB(on_taint_change, addr, size);
}

bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    if (taintEnabled) {
        return tb->llvm_tc_ptr ? false : true /* invalidate! */;
    }
    return false;
}

/**
 * @brief Basic initialization for `taint2` plugin.
 *
 * @note Taint propagation won't happen before you also call `taint2_enable_taint()`.
 */
bool init_plugin(void *self) {
    taint2_plugin = self;

    // set required panda options
    panda_enable_memcb();
    panda_disable_tb_chaining();

    // hook taint2 callbacks
#ifdef TAINT2_HYPERCALLS
    panda_cb pcb;
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(taint2_plugin, PANDA_CB_GUEST_HYPERCALL, pcb);
#endif

    // parse arguments
    panda_arg_list *args = panda_get_args("taint2");
    tainted_pointer = !panda_parse_bool_opt(args, "no_tp", "track taint through pointer dereference");
    std::cerr << PANDA_MSG "propagation via pointer dereference " << PANDA_FLAG_STATUS(tainted_pointer) << std::endl;
    inline_taint = panda_parse_bool_opt(args, "inline", "inline taint operations");
    std::cerr << PANDA_MSG "taint operations inlining " << PANDA_FLAG_STATUS(inline_taint) << std::endl;
    optimize_llvm = panda_parse_bool_opt(args, "opt", "run LLVM optimization on taint");
    std::cerr << PANDA_MSG "LLVM optimizations " << PANDA_FLAG_STATUS(optimize_llvm) << std::endl;
    debug_taint = panda_parse_bool_opt(args, "debug", "enable taint debugging");
    std::cerr << PANDA_MSG "taint debugging " << PANDA_FLAG_STATUS(debug_taint) << std::endl;

    // load dependencies
    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    return true;
}

void uninit_plugin(void *self) {
    if (shadow) {
        delete shadow;
        shadow = nullptr;
    }

    panda_disable_llvm();
    panda_disable_memcb();
    panda_enable_tb_chaining();
}
