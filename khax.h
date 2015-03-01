#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Initialize and do the initial pwning of the ARM11 kernel.
Result khaxInit();
// Shut down libctrkhax
Result khaxDestroy();

// Call an arbitrary function from ARM11 kernel mode.
Result khaxKernelCall(void (*callback)(void *context), void *context);

#ifdef __cplusplus
}
#endif
