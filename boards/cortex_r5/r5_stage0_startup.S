/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 EoS Project
 *
 * @file r5_stage0_startup.S
 * @brief Cortex-R5 stage-0 reset entry.
 *
 * Why this file exists (#137): the generic stage0/reset_entry.c is written
 * for Cortex-M -- its vector table lives in .isr_vector and holds addresses
 * (initial SP, then handler addresses), the shape a Cortex-M core fetches.
 * The cortex_r5 linker script keeps .vectors instead, and a Cortex-R core
 * fetches an *instruction* from each vector entry, not an address. Nothing
 * in the tree emitted .vectors, so --gc-sections discarded the whole
 * stage-0 and ebldr_stage0.bin linked to 0 bytes. This file emits the
 * .vectors section in the Cortex-R shape: eight branch instructions.
 *
 * Reset leaves the core in SVC mode with IRQ/FIQ disabled; stage-0 runs
 * entirely in SVC mode, so only the SVC stack is set up here.
 */

    .syntax unified
    .cpu cortex-r5
    .arm

    .section .vectors, "ax"
    .global r5_vectors
    .type r5_vectors, %object
r5_vectors:
    b r5_reset_entry            /* 0x00 reset */
    b r5_undef_handler          /* 0x04 undefined instruction */
    b r5_svc_handler            /* 0x08 supervisor call */
    b r5_prefetch_abort_handler /* 0x0C prefetch abort */
    b r5_data_abort_handler     /* 0x10 data abort */
    b .                         /* 0x14 reserved: hang */
    b r5_irq_handler            /* 0x18 IRQ */
    b r5_fiq_handler            /* 0x1C FIQ */

    .text
    .global r5_reset_entry
    .type r5_reset_entry, %function
r5_reset_entry:
    /* Point the SVC stack at the top of BTCM (_estack). */
    ldr sp, =_estack

    /* Copy .data from its load address (ATCM) to its runtime address (BTCM). */
    ldr r0, =_sdata
    ldr r1, =_edata
    ldr r2, =_sidata
    cmp r0, r1
    beq .Lzero_bss
.Lcopy_loop:
    ldr r3, [r2], #4
    str r3, [r0], #4
    cmp r0, r1
    bne .Lcopy_loop

.Lzero_bss:
    /* Zero .bss. */
    ldr r0, =_sbss
    ldr r1, =_ebss
    mov r2, #0
    cmp r0, r1
    beq .Lenter
.Lzero_loop:
    str r2, [r0], #4
    cmp r0, r1
    bne .Lzero_loop

.Lenter:
    /* Same entry sequence as the Cortex-M Reset_Handler. */
    bl ebldr_hw_init_minimal
    bl ebldr_stage0_main
    /* Should never return. */
    b .

    /* Minimal fault handlers: hang. Stage-0 is a few hundred bytes; there is
     * nothing useful to do on a fault before the application is up. Separate
     * labels so a debugger shows which vector hung. */
r5_undef_handler:
    b .
r5_svc_handler:
    b .
r5_prefetch_abort_handler:
    b .
r5_data_abort_handler:
    b .
r5_irq_handler:
    b .
r5_fiq_handler:
    b .
