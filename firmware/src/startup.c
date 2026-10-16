/* Minimal Cortex-M3 startup: vector table, Reset_Handler, default traps.
 * Nothing exotic - this is the standard shape of every small body-ECU
 * startup you will meet in the wild.
 */

#include <stdint.h>

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;

int main(void);

void Reset_Handler(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;

    while (dst < &_edata)          /* copy .data from flash to RAM */
        *(dst++) = *(src++);
    dst = &_sbss;
    while (dst < &_ebss)           /* zero .bss */
        *(dst++) = 0u;

    (void)main();
    for (;;)                       /* main() never returns on this target */
        ;
}

void Default_Handler(void)
{
    for (;;)
        ;
}

/* Weak aliases so the vector table reads like real firmware: named IRQs
 * that all funnel into Default_Handler until someone implements them. */
void NMI_Handler(void)       __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void)       __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void)    __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void CAN1_RX0_IRQHandler(void) __attribute__((weak, alias("Default_Handler")));
void CAN1_TX_IRQHandler(void)  __attribute__((weak, alias("Default_Handler")));
void TIM3_IRQHandler(void)     __attribute__((weak, alias("Default_Handler")));
void USART2_IRQHandler(void)   __attribute__((weak, alias("Default_Handler")));

__attribute__((used, section(".isr_vector")))
void (*const vector_table[])(void) = {
    (void (*)(void))(&_estack),  /* 0: initial stack pointer      */
    Reset_Handler,               /* 1: reset                      */
    NMI_Handler,                 /* 2: NMI                        */
    HardFault_Handler,           /* 3: hard fault                 */
    0, 0, 0, 0,                  /* 4-7: reserved                 */
    0, 0, 0, 0, 0, 0, 0,         /* 8-14: reserved                */
    SVC_Handler,                 /* 15: SVCall                    */
    0, 0,                        /* 16-17: debug/pend             */
    SysTick_Handler,             /* 18: systick                   */
    CAN1_RX0_IRQHandler,         /* 19: CAN RX                    */
    CAN1_TX_IRQHandler,          /* 20: CAN TX                    */
    TIM3_IRQHandler,             /* 21: timer                     */
    USART2_IRQHandler,           /* 22: USART                     */
};
