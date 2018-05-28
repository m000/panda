#include <glib.h>

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include "panda/plugin.h"

static bool cs_initialized;
static csh cs_handle_32;
#if defined(TARGET_X86_64)
static csh cs_handle_64;
#endif

static inline csh disas_handle(CPUArchState* env) {
#if defined(TARGET_X86_64)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#elif defined(TARGET_I386)
    csh handle = cs_handle_32;
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;
    if (env->thumb) {
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    } else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }
#elif defined(TARGET_PPC)
    csh handle = cs_handle_32;
#endif
    return handle;
}

static inline bool disas_init() {
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
        return false;
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#endif

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#endif
    return true;
}

void disas_block(CPUArchState* env, target_ulong addr, int size) {
    if (!cs_initialized) {
        disas_init();
    }

    uint8_t *buf = (uint8_t *)g_malloc(size * sizeof(uint8_t));
    if (panda_virtual_memory_rw(ENV_GET_CPU(env), addr, buf, size, 0) < 0) {
        g_free(buf);
        return;
    }

    csh handle = disas_handle(env);
    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, size, addr, 0, &insn);

    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            printf("\t0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    g_free(buf);
    return;
}

/* vim: set tabstop=4 softtabstop=4 expandtab: */
