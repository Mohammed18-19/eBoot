// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
// ISO/IEC 25000 | ISO/IEC/IEEE 15288:2023

/**
 * @file test_multicore.c
 * @brief Unit tests for multicore boot management
 */

#include "eos_multicore.h"
#include "eos_hal.h"
#include "eos_image.h"
#include "eos_types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        printf("  %-50s ", #name); \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } \
    static void name(void)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

/* Mock multicore ops */
static eos_core_state_t mock_states[EOS_MAX_CORES];
static int mock_start_count = 0;

static int mock_start_core(const eos_core_config_t *cfg)
{
    if (cfg->core_id >= EOS_MAX_CORES) return EOS_ERR_INVALID;
    mock_states[cfg->core_id] = EOS_CORE_STATE_RUNNING;
    mock_start_count++;
    return EOS_OK;
}

static int mock_stop_core(uint8_t core_id)
{
    if (core_id >= EOS_MAX_CORES) return EOS_ERR_INVALID;
    mock_states[core_id] = EOS_CORE_STATE_STOPPED;
    return EOS_OK;
}

static eos_core_state_t mock_get_state(uint8_t core_id)
{
    if (core_id >= EOS_MAX_CORES) return EOS_CORE_STATE_OFF;
    return mock_states[core_id];
}

static uint8_t mock_get_count(void) { return 4; }
static uint8_t mock_get_current(void) { return 0; }

static const eos_multicore_ops_t mock_mc_ops = {
    .start_core = mock_start_core,
    .stop_core = mock_stop_core,
    .reset_core = NULL,
    .get_core_state = mock_get_state,
    .send_ipi = NULL,
    .get_core_count = mock_get_count,
    .get_current_core = mock_get_current,
};

/* ---- Simulated board and image verification, for the AMP slot path ----
 *
 * eos_multicore_start() in AMP mode reads the slot through the HAL and then
 * verifies what it finds, so these tests need slot geometry and scriptable
 * verification results. Only slot_a_addr matters here; every other
 * eos_board_ops_t accessor NULL-guards, so the rest stays zeroed.
 *
 * The three eos_image_* definitions below override eboot_core's real ones at
 * link time -- the same technique test_slot_manager.c uses -- so each stage
 * can be failed independently without building and signing a real image. */

#define AMP_SLOT_A_ADDR   0x10000u
#define AMP_IMAGE_ENTRY   0x20000u

static const eos_board_ops_t sim_board_ops = {
    .slot_a_addr = AMP_SLOT_A_ADDR,
    .slot_a_size = 0x10000u,
};

static int      parse_result;
static int      integrity_result;
static int      signature_result;
static uint32_t image_entry_addr;

int eos_image_parse_header(uint32_t addr, eos_image_header_t *out)
{
    if (!out || addr != AMP_SLOT_A_ADDR) return EOS_ERR_INVALID;
    if (parse_result != EOS_OK) return parse_result;

    memset(out, 0, sizeof(*out));
    out->magic      = EOS_IMG_MAGIC;
    out->entry_addr = image_entry_addr;
    return EOS_OK;
}

int eos_image_verify_integrity(const eos_image_header_t *hdr, uint32_t addr)
{
    if (!hdr || addr != AMP_SLOT_A_ADDR) return EOS_ERR_INVALID;
    return integrity_result;
}

int eos_image_verify_signature(const eos_image_header_t *hdr)
{
    if (!hdr) return EOS_ERR_INVALID;
    return signature_result;
}

static void mc_setup(void)
{
    memset(mock_states, 0, sizeof(mock_states));
    mock_states[0] = EOS_CORE_STATE_RUNNING;  /* primary core is running */
    mock_start_count = 0;
    parse_result     = EOS_OK;
    integrity_result = EOS_OK;
    signature_result = EOS_OK;
    image_entry_addr = AMP_IMAGE_ENTRY;
    eos_hal_init(&sim_board_ops);
    eos_multicore_init(&mock_mc_ops);
}

/** Config for the AMP slot path, shaped as eos_multicore_start_amp() builds it. */
static eos_core_config_t amp_cfg(void)
{
    eos_core_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id    = 1;
    cfg.arch       = EOS_ARCH_ARM_R5;
    cfg.mode       = EOS_CORE_AMP;
    cfg.method     = EOS_START_AUTO;
    cfg.entry_addr = AMP_IMAGE_ENTRY;
    cfg.image_slot = EOS_SLOT_A;
    return cfg;
}

TEST(test_init)
{
    mc_setup();
    ASSERT(eos_multicore_count() == 4);
    ASSERT(eos_multicore_current() == 0);
    ASSERT(eos_multicore_get_state(0) == EOS_CORE_STATE_RUNNING);
}

TEST(test_init_null)
{
    ASSERT(eos_multicore_init(NULL) == EOS_ERR_INVALID);
}

TEST(test_start_smp)
{
    mc_setup();
    int rc = eos_multicore_start_smp(1, 0x08020000, 0x20010000);
    ASSERT(rc == EOS_OK);
    ASSERT(mock_start_count == 1);
    ASSERT(eos_multicore_get_state(1) == EOS_CORE_STATE_RUNNING);
}

TEST(test_cannot_restart_primary)
{
    mc_setup();
    eos_core_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 0;
    cfg.entry_addr = 0x08000000;
    ASSERT(eos_multicore_start(&cfg) == EOS_ERR_INVALID);
}

TEST(test_stop_core)
{
    mc_setup();
    eos_multicore_start_smp(1, 0x08020000, 0x20010000);
    ASSERT(eos_multicore_get_state(1) == EOS_CORE_STATE_RUNNING);

    int rc = eos_multicore_stop(1);
    ASSERT(rc == EOS_OK);
    ASSERT(eos_multicore_get_state(1) == EOS_CORE_STATE_STOPPED);
}

TEST(test_cannot_stop_primary)
{
    mc_setup();
    ASSERT(eos_multicore_stop(0) == EOS_ERR_INVALID);
}

TEST(test_start_requires_entry_addr)
{
    mc_setup();
    eos_core_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.entry_addr = 0;  /* invalid */
    ASSERT(eos_multicore_start(&cfg) == EOS_ERR_INVALID);
}

TEST(test_boot_all)
{
    mc_setup();
    eos_core_config_t configs[3];
    memset(configs, 0, sizeof(configs));

    configs[0].core_id = 0;  /* primary — will be skipped */
    configs[0].entry_addr = 0x08000000;

    configs[1].core_id = 1;
    configs[1].entry_addr = 0x08020000;
    configs[1].mode = EOS_CORE_SMP;

    configs[2].core_id = 2;
    configs[2].entry_addr = 0x08040000;
    configs[2].mode = EOS_CORE_SMP;

    int rc = eos_multicore_boot_all(configs, 3);
    ASSERT(rc == EOS_OK);
    ASSERT(mock_start_count == 2);  /* only cores 1 and 2 */
}

TEST(test_invalid_core_id)
{
    mc_setup();
    ASSERT(eos_multicore_get_state(EOS_MAX_CORES) == EOS_CORE_STATE_OFF);
    ASSERT(eos_multicore_stop(EOS_MAX_CORES) == EOS_ERR_INVALID);
}

TEST(test_ipi_mailbox_fallback)
{
    mc_setup();
    uint32_t dummy_mailbox = 0;
    
    eos_core_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.entry_addr = 0x08020000;
    cfg.mailbox_addr = (uintptr_t)&dummy_mailbox;
    
    int rc = eos_multicore_start(&cfg);
    ASSERT(rc == EOS_OK);
    
    rc = eos_multicore_send_ipi(1, 0xDEADBEEF);
    ASSERT(rc == EOS_OK);
    ASSERT(dummy_mailbox == 0xDEADBEEF);

    /* Test unaligned mailbox_addr */
    cfg.mailbox_addr = ((uintptr_t)&dummy_mailbox) | 1;
    rc = eos_multicore_start(&cfg);
    ASSERT(rc == EOS_OK);
    
    rc = eos_multicore_send_ipi(1, 0xCAFEBABE);
    ASSERT(rc == EOS_ERR_INVALID);
    ASSERT(dummy_mailbox == 0xDEADBEEF);
}

/* ---- AMP slot verification ----
 *
 * The AMP path parsed the slot header and started the core on it. A header
 * parses whenever the magic and sizes are well formed, which an attacker who
 * can write the slot controls completely, so the core ran unauthenticated
 * code. These pin each stage. */

TEST(test_amp_starts_a_verified_image)
{
    mc_setup();
    eos_core_config_t cfg = amp_cfg();
    ASSERT(eos_multicore_start(&cfg) == EOS_OK);
    ASSERT(mock_start_count == 1);
    ASSERT(mock_states[1] == EOS_CORE_STATE_RUNNING);
}

TEST(test_amp_refuses_a_failed_signature)
{
    mc_setup();
    signature_result = EOS_ERR_SIGNATURE;
    eos_core_config_t cfg = amp_cfg();
    ASSERT(eos_multicore_start(&cfg) == EOS_ERR_SIGNATURE);
    ASSERT(mock_start_count == 0);
    ASSERT(mock_states[1] != EOS_CORE_STATE_RUNNING);
}

TEST(test_amp_refuses_a_failed_integrity_check)
{
    mc_setup();
    integrity_result = EOS_ERR_CRC;
    eos_core_config_t cfg = amp_cfg();
    ASSERT(eos_multicore_start(&cfg) == EOS_ERR_CRC);
    ASSERT(mock_start_count == 0);
}

/* A verified image the core then does not branch into is verification
 * theatre, so a config whose entry_addr is not the signed header's is
 * refused. eos_multicore_start_amp() always agrees with the header. */
TEST(test_amp_refuses_an_entry_addr_the_image_does_not_name)
{
    mc_setup();
    eos_core_config_t cfg = amp_cfg();
    cfg.entry_addr = AMP_IMAGE_ENTRY + 4;
    ASSERT(eos_multicore_start(&cfg) == EOS_ERR_INVALID);
    ASSERT(mock_start_count == 0);
}

/* The wrapper derives entry_addr from the same header, so it inherits every
 * check above rather than carrying its own copy of them. */
TEST(test_amp_wrapper_refuses_a_failed_signature)
{
    mc_setup();
    signature_result = EOS_ERR_SIGNATURE;
    ASSERT(eos_multicore_start_amp(1, EOS_SLOT_A, EOS_ARCH_ARM_R5)
           == EOS_ERR_SIGNATURE);
    ASSERT(mock_start_count == 0);
}

int main(void)
{
    printf("=== eBootloader: Multicore Unit Tests ===\n\n");

    run_test_init();
    run_test_init_null();
    run_test_start_smp();
    run_test_cannot_restart_primary();
    run_test_stop_core();
    run_test_cannot_stop_primary();
    run_test_start_requires_entry_addr();
    run_test_boot_all();
    run_test_invalid_core_id();
    run_test_ipi_mailbox_fallback();
    run_test_amp_starts_a_verified_image();
    run_test_amp_refuses_a_failed_signature();
    run_test_amp_refuses_a_failed_integrity_check();
    run_test_amp_refuses_an_entry_addr_the_image_does_not_name();
    run_test_amp_wrapper_refuses_a_failed_signature();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
