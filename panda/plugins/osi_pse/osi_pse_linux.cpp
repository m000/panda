/*!
 * @file osi_pse_linux.cpp
 * @brief Linux implementation for process-level events.
 *
 * To identify when a process is created or destroyed, an FSM is implemented.
 * A sketch of the implemented FSM can be seen in: ...
 * A crucial point to get the implementation right is that we have to be
 * extremely careful about the assumptions we make regarding the ordering
 * of events inside the kernel.
 * This is particularly true for the case of the task scheduler: if *any*
 * assumption is made about the scheduling order of processes, with a long
 * enough trace, you will stumble on a case where the assumption is wrong.
 *
 * @author Manolis Stamatogiannakis manolis.stamatogiannakis@vu.nl
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <cstdio>
#include <cstdint>
#include <glib.h>
#include <map>
#include <bitset>

#define LOG_PANDALN_FILE stderr
#if PANDA_LOG_LEVEL < PANDA_LOG_DEBUG
#define LOG_DEBUG_NL
#else
#define LOG_DEBUG_NL fputc('\n', LOG_DEBUG_FILE)
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/common.h"

// osi plugin
#include "osi/osi_types.h"
#include "osi/os_intro.h"
#include "osi/osi_ext.h"

// syscalls2 plugin
#include "syscalls2/syscalls_numbers.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

// set the scnum namespace alias
#if defined(TARGET_I386)
namespace scnum = syscalls2::linux::x86; // XXX: will not work for x86_64
#elif defined(TARGET_ARM)
namespace scnum = syscalls2::linux::arm;
#elif defined(TARGET_PPC)
namespace scnum = syscalls2::linux::arm; // XXX: will not work for ppc
#else
#error Unsupported platform.
#endif

#include "osi_pse.h"
#include "osi_pse_linux.h"

extern "C" {
bool init_osi_pse_linux(void *);
void uninit_osi_pse_linux(void *);
}

static LPTracker lpt;
process_info_t *p_prev = nullptr;
target_ptr_t taskd_guess = ASID0;

/**
 * @brief Macro that unpacks references returned from get_current_process_info().
 * Two versions are supplied:
 *  - The first uses C++17 structured bindings.
 *  - The second uses std::get as a workaround.
 *
 *  @see https://skebanga.github.io/structured-bindings/
 */
#if __cplusplus >= 201703L
#define GET_PROCESS_INFO \
    LOG_DEBUG_NL; \
    auto [ h, p, pexists ] = lpt.procinfo_current(cpu);
#else
#define GET_PROCESS_INFO \
    LOG_DEBUG_NL; \
    auto __process_info_tuple = lpt.procinfo_current(cpu); \
    auto& UNUSED(h) = std::get<0>(__process_info_tuple); \
    auto& UNUSED(p) = std::get<1>(__process_info_tuple); \
    auto& UNUSED(pexists) = std::get<2>(__process_info_tuple);
#endif

/**
 * @brief Checks if \p h corresponds to the guessed taskd_guess.
 * Successfully guessing this at the time of the context switch
 * is a confidence test that our LPFSM is updated correctly.
 * It also allows as to run any callbacks we may need to run
 * at the guess location.
 */
void taskd_guess_check(CPUState *cpu, OsiProcHandle *h, process_info_t &p) {
    const char *UNUSED(status);
    target_ptr_t UNUSED(taskd_guess_sav) = taskd_guess;
    bool fail = false;
    if (taskd_guess == h->taskd) {
        status = "ok";
    } else if (p.fsm.state == LPFSM::State::VFC) {
        status = "ok (vfc)";
        taskd_guess = h->taskd;
    } else if (p.fsm.state == LPFSM::State::VFP && p.vforkc != nullptr &&
               p.vforkc->handle.taskd == taskd_guess) {
        status = "ok (vfp)";
        taskd_guess = h->taskd;
    } else {
        status = "fail";
        p.vdump(cpu);
        taskd_guess = h->taskd;
        fail = true;
    }

    if (fail) {
        LOG_DEBUG("%s: %-10s guess=" TARGET_PTR_FMT " real=" TARGET_PTR_FMT,
                  __func__, status, taskd_guess_sav, taskd_guess);
    } else {
        //LOG_DEBUG("%s: %-10s", __func__, status);
        LOG_DEBUG("%s: %-10s guess=" TARGET_PTR_FMT " real=" TARGET_PTR_FMT,
                  __func__, status, taskd_guess_sav, taskd_guess);
    }
}

/**
 * @brief Handles the return of sys_kill syscall. If the return
 * status indicates success and the signal sent results in the
 * termination of the receiving process, the state of the LPFSM
 * is set KILL.
 * @note Signals that will result in the graceful termination of
 * the receiving process (i.e. via sys_exit_group) need not be
 * handled here.
 */
void handle_kill_return(CPUState *cpu, target_ptr_t pc, int32_t pid, int32_t sig) {
    // Only process if call succeeds and the signal is of interest.
    target_long r = panda_get_retval(cpu);
    if (r != 0 || !(sig == 9 || sig == 2)) {
        return;
    }
    // XXX: also 3, 4, 6?

    // XXX: Negative/zero pids have special meaning. Not implemented.
    if (pid <= 0) {
        LOG_ERROR("Sending signal to pid " TARGET_FMT_ld " not supported. "
                  "Read kill(2) manual page on how to implement support for "
                  "this case.", (target_long)pid);
        assert(false && "sent signal to unsupported target");
    }

    // Create and init: OsiProcHandle *h; process_info_t &p; bool pexists;
    GET_PROCESS_INFO;
    assert(pexists && "kill from unknown process");

    char *s = g_strdup_printf("kill -%d " TARGET_FMT_ld " -> " TARGET_FMT_ld,
                              sig, (target_long)pid, r);
    p.vdump(cpu, s);
    g_free(s);

    process_info_t &pkilled = lpt.procinfo_by_pid(pid);
    pkilled.fsm.save_state();
    pkilled.fsm.state = LPFSM::State::KILL;
    pkilled.vdump_transition(cpu);

    free_osiprochandle(h);
}

/**
 * @brief Handles the return of syscalls related to process creation
 * or destruction.
 * @note Syscalls that can be handled without waiting their return
 * are handled in handle_sys_enter(). Syscalls that we need to wait
 * their return, but we also need to inspect their call arguments
 * are handled in separate callbacks (e.g. handle_kill_return()).
 * See IMPLEMENTATION.md for details.
 */
void handle_sys_return(CPUState *cpu, target_ulong pc,
                       const syscall_info_t *call, const syscall_ctx_t *ctx) {
    // Create and init: OsiProcHandle *h; process_info_t &p; bool pexists;
    GET_PROCESS_INFO;
    const char *syscall = (call == nullptr) ? "N/A" : call->name;
    p.dump("SYSR", syscall, "");

    switch (p.fsm.state) {
        case LPFSM::State::CLN:
        {
            // Return of sys_clone.
            // Add new process by ppid since we don't have any other
            // info for the child process.
            // QQQ: Can the child be scheduled before the return?
            process_info_t *ppnew = lpt.AddNewByPPID(cpu, p.pid);
            if (ppnew != nullptr) {
                p.fsm.state = LPFSM::State::RUN;
            } else {
                // no new process found - yet
                break;
            }
        } break;
        // ----------------------------------------------------------
        case LPFSM::State::INIT:
        case LPFSM::State::END:
        {
            // Return of sys_vfork.
            // It is an error when any other syscall returns and the
            // LPFSM state is INIT or RUN.
            // Unlike with other syscalls, PANDA will not trigger this
            // callback in the context of the calling process, but in
            // the context of the created process.
            // Moreover, calling (parent) process and created (child)
            // process will be sharing their asid for a while. This
            // means that there may be a context switch between the two
            // without triggering PANDA_CB_ASID_CHANGED.
            // See IMPLEMENTATION.md for details.
            switch (call->no) {
                case scnum::sys_vfork:
                {
                    LOG_DEBUG("VFORK");
                    process_info_t &pchild = p;
                    if (pexists) {
                        assert(pchild.fsm.state == LPFSM::State::END);
                        pchild.reset(cpu, h);
                    }

                    // Get parent's asid mapping using the shared asid.
                    auto a2t_it = lpt.asids.find(pchild.handle.asid);
                    assert(a2t_it != lpt.asids.end());
                    assert(a2t_it->second != pchild.handle.taskd);

                    // Get parent process info.
                    process_info_t &pparent = lpt.procinfo_by_taskd(a2t_it->second);
                    assert(pchild.handle.asid == pparent.handle.asid);
                    assert(pchild.handle.taskd != pparent.handle.taskd);

                    // Update asid mapping to point to child process.
                    a2t_it->second = pchild.handle.taskd;

                    // Update the expected taskd.
                    assert(taskd_guess == pparent.handle.taskd);
                    //taskd_guess = pchild.handle.taskd;
               
                    // Set state and parent pointers.
                    pchild.fsm.state = LPFSM::State::VFC;
                    pchild.vforkp = &pparent;
                    pchild.vforkc = nullptr;
                    pparent.fsm.state = LPFSM::State::VFP;
                    pparent.vforkp = nullptr;
                    pparent.vforkc = &pchild;

                    pchild.vdump(cpu);
#if defined(OSI_PSE_ALT_VFORK)
                    // Alternate handling of the sys_vfork-sys_execve sequence.
                    //
                    // By default, the transient child process is ignored,
                    // in order to guarantee to plugins using osi_pse that
                    // there is a one-to-one mapping of asids to processes.
                    // This is typically required if the plugins use asids
                    // as the key to some C++ map structure.
                    // If this guarantee is not needed, you can define the
                    // OSI_PSE_ALT_VFORK macro, which will result in a start
                    // and an end callback to be run for the transient child
                    // process.
                    pchild.run_cb_start(cpu);
#endif
                } break;
                default:
                    LOG_ERROR("Unexpected return for syscall %s at state %s.",
                              syscall, p.fsm.c_str());
                    p.vdump(cpu);
                    assert(false && "unexpected system call return");
                    break;
            }
        } break;
        // ----------------------------------------------------------
        default:
        {
            // Just a normal syscall return.
            // nop
        } break;
    }
    free_osiprochandle(h);
}

/**
 * @brief Handles the start of syscalls related to process creation
 * or destruction. For processes with their LPFSM in the RUN state, 
 * this typically means that they transition to another LPFSM state.
 * For processes with LPFSM in some other state, this signifies the
 * transition to the RUN or END states, perhaps after the creation
 * of a new process.
 * See IMPLEMENTATION.md for details.
 */
void handle_sys_enter(CPUState *cpu, target_ptr_t pc,
                      const syscall_info_t *call, const syscall_ctx_t *ctx) {
    // Create and init: OsiProcHandle *h; process_info_t &p; bool pexists;
    GET_PROCESS_INFO;
    const char *syscall = (call == nullptr) ? "N/A" : call->name;

    taskd_guess_check(cpu, h, p);

    p.fsm.save_state();
    switch (p.fsm.state) {
        case LPFSM::State::INIT:
        case LPFSM::State::RUN:
        case LPFSM::State::KILL: {
            if (p.fsm.state == LPFSM::State::INIT) {
                // Run on_process_start if it is still pending.
                // Observed for generic kworker tasks that "transform" to
                // regular user processes.
                // XXX: We need to warn about the delayed callback.
                // This is because this code runs *after* any syscall-specific
                // callbacks a plugin may have registered, due to the specifics
                // of syscalls2 implementation. I.e. the syscall-specific
                // callback will be run before the plugin has been notified
                // about the new process. Note that this will not impact most
                // plugins, as the first syscall of the new process is usually
                // of little interest (e.g. sys_brk).
                if (!p.ran_cb_start_) {
                    LOG_WARNING("late on_process_start callback for " PH_FMT
                                ".", PH_ARGS(p.handle));
                    p.run_cb_start(cpu);
                }
                p.fsm.state = LPFSM::State::RUN;
            } else if (p.fsm.state == LPFSM::State::KILL) {
                LOG_DEBUG("survived kill!");
                p.fsm.state = LPFSM::State::RUN;
            }
            switch (call->no) {
                case scnum::sys_clone:
                    p.fsm.state = LPFSM::State::CLN;
                    break;
                case scnum::sys_execve:
                    p.fsm.state = LPFSM::State::EXE;
                    break;
                case scnum::sys_exit_group:
                    p.fsm.state = LPFSM::State::END;
                    assert(lpt.asids.erase(p.handle.asid));
                    p.run_cb_end(cpu);
                    break;
                case scnum::sys_exit:
                    // XXX: This hasn't been observed in practice.
                    p.fsm.state = LPFSM::State::END;
                    assert(lpt.asids.erase(p.handle.asid));
                    p.run_cb_end(cpu);
                    assert(false && "handling of exit not tested");
                    break;
                default:
                    break;
            }
        } break;
        // ----------------------------------------------------------
        case LPFSM::State::VFP:
        {
            assert(p.vforkp == nullptr && p.vforkc != nullptr && "invalid FSM state");
            process_info_t &pparent = p;
            process_info_t &pchild = *p.vforkc;
            assert(pchild.ppid = pparent.pid);

            switch (call->no) {
#if defined(TARGET_I386)
                case scnum::sys_waitpid:
#endif
                case scnum::sys_wait4:
                    // Remain in VFP state, waiting for the child
                    // process to transition to RUN or EXE.
                    break;
                case scnum::sys_exit_group:
                    // Transition to END state after making sure that
                    // the child process has transitioned to RUN or EXE.
                    // XXX: This hasn't been observed in practice.
                    assert(pchild.fsm.state == LPFSM::State::RUN || pchild.fsm.state == LPFSM::State::EXE);
                    pparent.fsm.state = LPFSM::State::END;
                    assert(lpt.asids.erase(pparent.handle.asid));
                    pparent.run_cb_end(cpu);
                    break;
                case scnum::sys_exit:
                    // Transition to END state after making sure that
                    // the child process has transitioned to RUN or EXE.
                    // XXX: This hasn't been observed in practice.
                    assert(pchild.fsm.state == LPFSM::State::RUN || pchild.fsm.state == LPFSM::State::EXE);
                    pparent.fsm.state = LPFSM::State::END;
                    assert(lpt.asids.erase(pparent.handle.asid));
                    pparent.run_cb_end(cpu);
                    assert(false && "handling of exit not tested");
                    break;
                default:
                    // Return to RUN state, after checking that the
                    // child process is also in RUN or EXE state.
                    assert(pchild.fsm.state == LPFSM::State::RUN || pchild.fsm.state == LPFSM::State::EXE);
                    pparent.fsm.state = LPFSM::State::RUN;
                    pparent.vforkp = nullptr;
                    pparent.vforkc = nullptr;

                    // Restore asid to taskd mapping for parent.
                    lpt.UpdateASIDMapping(pchild.handle.asid, pparent.handle.taskd);
                    break;
            }
        } break;
        // ----------------------------------------------------------
        case LPFSM::State::VFC:
        {
            assert(p.vforkp != nullptr && p.vforkc == nullptr && "invalid FSM state");
            process_info_t &pparent = *p.vforkp;
            process_info_t &pchild = p;
            assert(pchild.ppid = pparent.pid);

            switch (call->no) {
                case scnum::sys_dup2:
                case scnum::sys_close:
                    // Whitelisted syscalls - allowed before sys_execve.
                    break;
                case scnum::sys_execve:
                    // Change state to EXE. If sys_execve turns out to
                    // be successful, this concludes the handling of
                    // sys_vfork.
                    pchild.fsm.state = LPFSM::State::EXE;
                    break;
                default:
                    // Non whitelisted syscalls. This is not necessarily
                    // an error, but raise a warning anyway.
                    // XXX: This hasn't been observed in practice.
                    LOG_WARNING("Unexpected syscall %s for sys_vfork child.",
                                call->name);
                    break;
            }
        } break;
        // ----------------------------------------------------------
        case LPFSM::State::EXE:
        {
            switch (call->no) {
                case scnum::sys_execve:
                    if (p.vforkp == nullptr) {
                        // Failed sys_execve - wait for retry.
                    } else {
                        // Failed sys_execve - wait for retry.
                        // Also make sure the parent is still in VFP state.
                        assert(p.vforkp->fsm.state == LPFSM::State::VFP);
                    }
                    break;
                case scnum::sys_exit_group:
                    p.fsm.state = LPFSM::State::END;
                    assert(lpt.asids.erase(p.handle.asid));
                    p.run_cb_end(cpu);
                    break;
                case scnum::sys_exit:
                    p.fsm.state = LPFSM::State::END;
                    assert(lpt.asids.erase(p.handle.asid));
                    p.run_cb_end(cpu);
                    assert(false && "handling of exit not tested");
                    break;
                case scnum::sys_brk:
                    // Success for sys_execve - sys_brk is typically the
                    // first syscall of the new process.
                    // Because of the handling in asid_changed_linux, we
                    // don't expect control flow to ever reach here.
                    //
                    // XXX: This hasn't been observed in practice.
                    // XXX: Because of the syscalls2 callbacks invocation
                    //      order, if control flow ever reaches here, the
                    //      callback for on_sys_break_enter will have already
                    //      been executed. This may affect the operation of
                    //      plugins that use both this callback and osi_pse.
                    LOG_ERROR("Unexpected syscall %s at state %s. "
                              "This hould have been handled earlier.",
                              syscall, p.fsm.c_str());
                    p.vdump(cpu);
                    assert(false && "unexpected sys_brk after sys_execve");
                    break;
                default:
                    LOG_ERROR("Unexpected syscall %s at state %s.",
                              syscall, p.fsm.c_str());
                    p.vdump(cpu);
                    assert(false && "unexpected syscall after sys_execve");
                    break;
            }
        } break;
        // ----------------------------------------------------------
        default:
        {
            LOG_ERROR("Unexpected syscall %s at state %s.",
                      syscall, p.fsm.c_str());
            p.vdump(cpu);
            assert(false && "unexpected system call" );
        } break;
    }

    p.vdump_transition(cpu);
    p.dump("SYSE", syscall, nullptr);
    free_osiprochandle(h);
}

/**
 * @brief Handles context switch events to updates the information for
 * the involved processes.
 * When this callback is executed the context switch hasn't yet
 * happened. This means that GET_PROCESS_INFO will not return the
 * process that will run next. The process that will run next needs
 * to be looked up using only its asid (\p next).
 * See IMPLEMENTATION.md for details.
 */
bool asid_changed_linux(CPUState *cpu, target_ptr_t current, target_ptr_t next) {
    // Create and init: OsiProcHandle *h; process_info_t &p; bool pexists;
    GET_PROCESS_INFO;
    process_info_t *pnext = nullptr;

    LOG_DEBUG("--- CS: " TARGET_PTR_FMT " -> " TARGET_PTR_FMT
              " %5s ---------------------------",
              current, next, p.fsm.c_str());

    // Sanity check. Process handle h is acquired using the cpu state.
    // Process information is indexed by h->taskd.
    // We verify that the retrieved process information is ok.
    assert(p.handle.asid == current ||          // process matches handle
           p.handle.asid == ASID0 ||            // kernel process - ignored
           p.fsm.state == LPFSM::State::END ||  // ended process cleanup
           (p.fsm.state == LPFSM::State::INIT && !pexists));  // new process

    p.fsm.save_state();
    switch (p.fsm.state) {
        case LPFSM::State::KERN:
        {
            // If the scheduled-out process is in KERN state, we generally
            // expect that the process to be scheduled-in already has an
            // asid to taskd mapping. There are some rare exceptions though.
            auto a2t_it = lpt.asids.find(next);
            if (a2t_it != lpt.asids.cend()) {
                // expected
                auto ps_it = lpt.ps.find(a2t_it->second);
                assert(ps_it != lpt.ps.end());
                pnext = &ps_it->second;
            } else {
                LOG_WARNING("An unknown asid appeared: " TARGET_PTR_FMT, next);
                pnext = lpt.AddNewByASID(cpu, next);
                if (pnext == nullptr) {
                    // If no process was found, it is not necessarily an error
                    // in the analysis code. It may be a transition to a kernel
                    // context that doesn't map to a process.
                    LOG_DEBUG_MSGPROC("kernel to kernel cs", p);
                    break;
                } else if (pnext->fsm.state == LPFSM::State::END) {
                    // Due to kernel preemptibility, an exiting process may
                    // be interrupted before its asid is cleared. In that
                    // case, AddNewByASID() will return an ended process.
                    LOG_DEBUG_MSGPROC("interrupted sys_exit_group", *pnext);
                    pnext->vdump(cpu);
                    break;
                } else {
                    process_info_t &parnext = lpt.procinfo_by_pid(pnext->ppid);
                    if (parnext.fsm.state == LPFSM::State::CLN) {
                        // Due to kernel preemtibility/non-determinism,
                        // a process created by sys_clone may run before the
                        // system call returns to its parent.
                        LOG_DEBUG_MSGPROC("odd sys_clone return order", *pnext);
                        parnext.fsm.state = LPFSM::State::RUN;
                        pnext->vdump(cpu);
                        pnext->run_cb_start(cpu);
                    } else {
                        // unexpected - fail to examine the case
                        assert(false && "unknown asid scheduled after kernel process");
                    }
                }
            }
        } break;
        case LPFSM::State::CLN:
        {
            // The scheduled-out process is still executing a sys_clone.
            // First check if parent or child process are scheduled next.
            if (next == current) {
                // Same asid for the scheduled-in and out processes. This is
                // part of the cloning process, but the new process is not
                // ready yet. Do nothing.
                pnext = &p;
            } else {
                // Different asids for the scheduled-in and out processes.
                // Check if the cloned process is ready.
                process_info_t *pnew = lpt.AddNewByPPID(cpu, p.pid);
                if (pnew != nullptr) {
                    p.fsm.state = LPFSM::State::RUN;
                    pnew->vdump(cpu);
                    pnew->run_cb_start(cpu);
                }

                // New process is the one to be scheduled next.
                if (pnew != nullptr && pnew->handle.asid == next) {
                    pnext = pnew;
                }
            }

            // No new process found or found but not scheduled next.
            if (pnext == nullptr) {
                auto a2t_it = lpt.asids.find(next);
                if (a2t_it != lpt.asids.cend()) {
                    // expected - some other process is scheduled
                    auto ps_it = lpt.ps.find(a2t_it->second);
                    assert(ps_it != lpt.ps.end());
                    pnext = &ps_it->second;
                } else {
                    // unexpected - fail to examine the case
                    LOG_ERROR("An unknown asid appeared: " TARGET_PTR_FMT, next);
                    pnext = lpt.AddNewByASID(cpu, next);
                    assert(pnext != nullptr);
                    pnext->vdump(cpu);
                    assert(false && "unknown asid scheduled after running process");
                }
            }
        } break;
        case LPFSM::State::EXE:
        {
            assert(p.handle.asid == current);
            LOG_DEBUG("X0");

            // Process created as a result of a sys_vfork-sys_execve sequence.
            if (p.vforkp != nullptr) {
                process_info_t &pchild = p;
                process_info_t &pparent = *p.vforkp;

                LOG_DEBUG("X1");
                if (pparent.fsm.state == LPFSM::State::VFP) {
                    LOG_DEBUG("parent fix");
                    // Update parent still in VFP state.
                    pparent.fsm.save_state();
                    pparent.fsm.state = LPFSM::State::RUN;
                    pparent.vforkp = nullptr;
                    pparent.vforkc = nullptr;
                    pparent.vdump_transition(cpu);

                    // Restore asid to taskd mapping for parent.
                    lpt.UpdateASIDMapping(pchild.handle.asid, pparent.handle.taskd);
                } else {
                    // Parent has already transitioned to another state.
                    // nop
                    LOG_DEBUG("parent ok");
                }

#if defined(OSI_PSE_ALT_VFORK)
                // Alternate handling of the sys_vfork-sys_execve sequence.
                // See details above.
                pchild.run_cb_end(cpu);
#endif

                // At this point the child process has its own asid.
                // Reset it and run the start callback.
                pchild.reset(cpu, h->taskd, next, true);
                lpt.AddASIDMapping(pchild.handle.asid, pchild.handle.taskd);
                pchild.vforkp = nullptr;
                pchild.vforkc = nullptr;
                pchild.run_cb_start(cpu);

                // Make sure that we're indeed switching to the new child.
                assert(pchild.ppid == pparent.pid);

                pnext = &pchild;
                break;
            }

            auto a2t_it = lpt.asids.find(next);

            // sys_execve - sans sys_vfork. No asid to taskd mapping.
            // We assume that this means that the scheduled-in process
            // is the result of sys_execve. Update current process and
            // add new mapping.
            if (a2t_it == lpt.asids.cend()) {
                target_pid_t pid_old = p.pid;
                target_pid_t ppid_old = p.ppid;

                // Remove current asid to taskd mapping.
                assert(lpt.asids.erase(p.handle.asid));

                // Run callbacks and update.
                p.run_cb_end(cpu);
                p.reset(cpu, h->taskd, next, true);
                lpt.AddASIDMapping(p.handle.asid, p.handle.taskd);
                p.run_cb_start(cpu);

                // Sanity check after reset.
                assert(p.pid == pid_old && p.ppid == ppid_old);

                pnext = &p;
                break;
            }

            // sys_execve - sans sys_vfork. Existing asid to taskd mapping.
            // This means that the scheduled-out process has not finished
            // with sys_execve, and the scheduled-in process is unrelated.
            // Only do some sanity checks.
            pnext = &lpt.procinfo_by_taskd(a2t_it->second);
            assert(pnext->fsm.state != LPFSM::State::END);
            assert(pnext->pid != p.pid);
        } break;
        case LPFSM::State::END:
        {
            if (h->asid == ASID0) {
                // Either the scheduled-out process has started terminating,
                // or a real kernel process. Attempt to find the next process
                // by asid. Failing is ok. The kernel often takes a turn after
                // an exiting process.
                assert(h->taskd == p.handle.taskd);
                auto a2t_it = lpt.asids.find(next);
                if (a2t_it != lpt.asids.cend()) {
                    auto ps_it = lpt.ps.find(a2t_it->second);
                    assert(ps_it != lpt.ps.end());
                    pnext = &ps_it->second;
                } else {
                    LOG_DEBUG_MSGPROC("exiting process to unknown", p);
                }
            } else if (h->asid == next) {
                // Weirdness: h->asid matches the scheduled-in process.
                // XXX: This has only been observed when the kernel
                // creates a user-level helper process. The process at
                // this point is still a generic kworker. We choose to
                // defer the start callback until the role of the new
                // process has been finalized.
                p.reset(cpu, h);
                lpt.AddASIDMapping(h->asid, h->taskd);
                LOG_DEBUG_MSGPROC("kworker to process", p);
                pnext = &p;
            } else {
                // XXX: This hasn't been observed in practice.
                // This block covers two cases:
                //      (a) h->asid == current
                //      (b) h->asid == <other value>
                // The first case has not been observed, because terminating
                // processes have already their asid reset (h->asid == ASID0).
                // The second case means that we have probably missed something
                // important, and that the osi_pse codebase needs fixing.
                LOG_ERROR("Unexpected asid " TARGET_PTR_FMT
                          " for process at state %s.", h->asid, p.fsm.c_str());
                p.vdump(cpu);
                assert(false && "unexpected asid for terminating process");
            }
        } break;
        case LPFSM::State::RUN:
        case LPFSM::State::KILL:
        default:
        {
            if (p.fsm.state == LPFSM::State::KILL) {
                // The scheduled-out process has already been killed.
                // Transition from KILL to END.
                p.fsm.state = LPFSM::State::END;
                assert(lpt.asids.erase(p.handle.asid));
                p.run_cb_end(cpu);
            }

            // If the scheduled-out process is in RUN/KILL/other state,
            // we expect that the process to be scheduled-in already has
            // an asid to taskd mapping.
            auto a2t_it = lpt.asids.find(next);
            if (a2t_it != lpt.asids.cend()) {
                // expected
                auto ps_it = lpt.ps.find(a2t_it->second);
                assert(ps_it != lpt.ps.end());
                pnext = &ps_it->second;
            } else if (p.fsm.state == LPFSM::State::END) {
                // KILL->END transition.
                // We have observed that the scheduled-in code may
                // be kernel code not associated with a process.
                LOG_DEBUG_MSGPROC("unknown code after kill", p);
            } else {
                // unexpected - fail to examine the case
                LOG_ERROR("An unknown asid appeared: " TARGET_PTR_FMT, next);
                pnext = lpt.AddNewByASID(cpu, next);
                assert(pnext != nullptr);
                pnext->vdump(cpu);
                assert(false && "unknown asid scheduled after running process");
            }
        } break;
    }
    p.vdump_transition(cpu);

    // Update taskd_guess based on the value of pnext. Being able to guess
    // this correctly, means that:
    //  - we can run the on_process_start callbacks here
    //  - we can make the INIT -> FSM transition on the first syscall
    if (pnext != nullptr) {
        taskd_guess = pnext->handle.taskd;
        LOG_DEBUG("coming up next: " PH_FMT, PH_ARGS(pnext->handle));
    } else {
        // This should only happen when switching to a kernel context
        // with no process associated with it.
        taskd_guess = ASID0;
        LOG_DEBUG("coming up next: ?");
    }

    free_osiprochandle(h);
    return false;
}

/** @brief Initializes process list at start of replay. */
void after_machine_init(CPUState *cpu) {
    LOG_DEBUG("--- INIT -----------------------------------------------------");
    int UNUSED(nadded) = lpt.initialize(cpu);
    LOG_DEBUG("--- INIT: %03d processes --------------------------------------", nadded);
}

/** @brief osi_pse - linux implementation initialization. */
bool init_osi_pse_linux(void *self) {
    assert(panda_os_familyno == OS_LINUX);

    // panda callbacks
    panda_cb pcb;
    pcb.after_machine_init = after_machine_init;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);
    pcb.asid_changed = asid_changed_linux;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    // syscalls2 callbacks
#if defined(TARGET_I386) || defined(TARGET_ARM)
    PPP_REG_CB("syscalls2", on_all_sys_enter2, handle_sys_enter);
    PPP_REG_CB("syscalls2", on_all_sys_return2, handle_sys_return);
    PPP_REG_CB("syscalls2", on_sys_kill_return, handle_kill_return);
#else
    // warn that no os-specific handlers are installed
    LOG_WARNING("Plugin has not been tested with %s!!! ", panda_os_family);
    LOG_WARNING("Continuing anyway.");
#endif

    return true;
}

/** @brief osi_pse - linux implementation cleanup. */
void uninit_osi_pse_linux(void *self) {
    // XXX: We don't have a CPUState pointer in this context.
    // This shouldn't be a problem as long as PANDA only
    // supports one virtual cpu.
    CPUState *cpu = first_cpu;

    // Initialize counters.
    uint32_t state_counts[LPFSM::kNumStates];
    memset(state_counts, 0, LPFSM::kNumStates * sizeof(uint32_t));
    uint32_t UNUSED(nactive) = 0;

    LOG_DEBUG("--- UNINIT ---------------------------------------------------");
    for (auto &ps_it : lpt.ps) {
        process_info_t &p = ps_it.second;
        state_counts[p.fsm.state]++;
        switch (p.fsm.state) {
            case LPFSM::State::INIT:
            case LPFSM::State::END:
            case LPFSM::State::KERN:
                break;
            default:
                nactive++;
                p.run_cb_end(cpu);
                break;
        }
    }
    LOG_INFO("Process states at the end of the trace:");
    for (uint32_t i = 0; i < LPFSM::kNumStates; i++) {
        if (state_counts[i] == 0) continue;
        LOG_INFO("\t%4s: %2u", LPFSM::state_str((LPFSM::State)i),
                 state_counts[i]);
    }
    LOG_DEBUG("--- UNINIT: %03d running processes --------------------------",
              nactive);

    lpt.ps.clear();
    lpt.asids.clear();
    LOG_INFO(PLUGIN_NAME " linux cleanup complete.");
}
/* vim:set tabstop=4 softtabstop=4 expandtab: */
