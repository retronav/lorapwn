MEMORY
{
  /* STM32F303RE has 512K FLASH and 64K RAM */
  FLASH : ORIGIN = 0x08000000, LENGTH = 512K
  RAM : ORIGIN = 0x20000000, LENGTH = 64K
}

/* Required for cortex-m-rt */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);