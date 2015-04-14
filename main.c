#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "khax.h"

#ifndef _MSC_VER
__attribute__((__naked__))
#endif
Result my_svcBackdoor(s32 (*callback)(void))
{
	__asm__ volatile(
		"svc 0x7B\n\t"
		"bx lr\n\t");
}

s32 g_backdoorResult = -1;

s32 dump_chunk_wrapper()
{
	__asm__ volatile("cpsid aif");
	g_backdoorResult = 0x6666abcd;
	return 0;
}

#ifndef LIBKHAX_AS_LIB
int main()
{
	// Initialize services
/*	srvInit();			// mandatory
	aptInit();			// mandatory
	hidInit(NULL);	// input (buttons, screen)*/
	gfxInitDefault();			// graphics
/*	fsInit();
	sdmcInit();
	hbInit();
	qtmInit();*/

	consoleInit(GFX_BOTTOM, NULL);

	consoleClear();

	Result result = khaxInit();
	printf("khaxInit returned %08lx\n", result);

	printf("backdoor returned %08lx\n", (my_svcBackdoor(dump_chunk_wrapper), g_backdoorResult));

	while (aptMainLoop())
	{
		// Wait next screen refresh
		gspWaitForVBlank();

		// Read which buttons are currently pressed 
		hidScanInput();
		u32 kDown = hidKeysDown();
		(void) kDown;
		u32 kHeld = hidKeysHeld();
		(void) kHeld;

		// If START is pressed, break loop and quit
		if (kDown & KEY_X){
			break;
		}

		//consoleClear();

		// Flush and swap framebuffers
		gfxFlushBuffers();
		gfxSwapBuffers();
	}

	// Exit services
/*	qtmExit();
	hbExit();
	sdmcExit();
	fsExit();*/
	gfxExit();
/*	hidExit();
	aptExit();
	srvExit();*/

	// Return to hbmenu
	return 0;
}
#endif
