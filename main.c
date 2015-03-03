#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "khax.h"

int main()
{
	// Initialize services
	srvInit();			// mandatory
	aptInit();			// mandatory
	hidInit(NULL);	// input (buttons, screen)
	gfxInitDefault();			// graphics
	fsInit();
	sdmcInit();
	hbInit();

	qtmInit();
	consoleInit(GFX_BOTTOM, NULL);

	consoleClear();

	Result result = khaxInit();
	printf("khaxInit returned %08lx\n", result);

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
	hbExit();
	sdmcExit();
	fsExit();
	gfxExit();
	hidExit();
	aptExit();
	srvExit();

	// Return to hbmenu
	return 0;
}
