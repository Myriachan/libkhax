#include <3ds.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

#define KHAX_DEBUG

#ifdef KHAX_DEBUG
	#define KHAX_printf printf
#else
	#define KHAX_printf static_cast<void>
#endif

#define KHAX_lengthof(...) (sizeof(__VA_ARGS__) / sizeof((__VA_ARGS__)[0]))

//------------------------------------------------------------------------------------------------
namespace KHAX
{
	//------------------------------------------------------------------------------------------------
	// Kernel and hardware version information.
	struct VersionData
	{
		// New 3DS?
		bool m_new3DS;
		// Kernel version number
		u32 m_kernelVersion;
		// Nominal version number lower bound (for informational purposes only)
		u32 m_nominalVersion;
		// Patch location in svcCreateThread
		u32 m_threadPatchAddress;
		// System call unlock patch location
		u32 m_syscallPatchAddress;
		// Kernel virtual address mapping of FCRAM
		u32 m_fcramVirtualAddress;
		// Physical mapping of FCRAM on this machine
		u32 m_fcramPhysicalAddress;
		// Physical size of FCRAM on this machine
		u32 m_fcramSize;

		// Convert a user-mode virtual address in the linear heap into a kernel-mode virtual
		// address using the version-specific information in this table entry.
		void *ConvertLinearUserVAToKernelVA(void *address) const;

		// Retrieve a VersionData for this kernel, or null if not recognized.
		static const VersionData *GetForCurrentSystem();

	private:
		// Table of these.
		static const VersionData s_versionTable[];
	};

	//------------------------------------------------------------------------------------------------
	// ARM11 kernel hack class.
	class MemChunkHax
	{
	public:
		// Construct using the version information for the current system.
		MemChunkHax(const VersionData *versionData)
		:	m_versionData(versionData),
			m_nextStep(1),
			m_overwriteMemory(nullptr),
			m_overwriteAllocated(0)
		{
		}

		// Free memory and such.
		~MemChunkHax();

		// Umm, don't copy this class.
		MemChunkHax(const MemChunkHax &) = delete;
		MemChunkHax &operator =(const MemChunkHax &) = delete;

		// Basic initialization.
		Result Step1_Initialize();
		// Allocate linear memory for the memchunkhax operation.
		Result Step2_AllocateMemory();
		// Free the second and fourth pages of the five.
		Result Step3_SurroundFree();

	private:
		// Version information.
		const VersionData *const m_versionData;
		// Next step number.
		int m_nextStep;

		// Free block structure in the kernel, the one used in the memchunkhax exploit.
		struct HeapFreeBlock
		{
			int m_count;
			HeapFreeBlock *m_next;
			HeapFreeBlock *m_prev;
			int m_unknown1;
			int m_unknown2;
		};

		// The layout of a memory page.
		union Page
		{
			unsigned char m_bytes[4096];
			HeapFreeBlock m_freeBlock;
		};

		// The linear memory allocated for the memchunkhax overwrite.
		struct OverwriteMemory
		{
			union
			{
				unsigned char m_bytes[6 * 4096];
				Page m_pages[6];
			};
		};
		OverwriteMemory *m_overwriteMemory;
		unsigned m_overwriteAllocated;
	};

	//------------------------------------------------------------------------------------------------
	// Make an error code
	inline Result MakeError(Result level, Result summary, Result module, Result error);
	enum : Result { KHAX_MODULE = 254 };
	// Check whether this system is a New 3DS.
	Result IsNew3DS(bool *answer, u32 kernelVersionAlreadyKnown = 0);
	// Simple gspwn copy, not using any fancy looping.
	Result SimpleGSPwn(void *dest, const void *src, std::size_t size, s64 waitNanoseconds);
}


//------------------------------------------------------------------------------------------------
//
// Class VersionData
//

//------------------------------------------------------------------------------------------------
// System version table
const KHAX::VersionData KHAX::VersionData::s_versionTable[] =
{
	// Old 3DS, old address layout
	{ false,  SYSTEM_VERSION(2, 34, 0), SYSTEM_VERSION(4, 1, 0), 0xEFF83C97, 0xEFF827CC, 0xF0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 35, 6), SYSTEM_VERSION(5, 0, 0), 0xEFF8372F, 0xEFF822A8, 0xF0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 36, 0), SYSTEM_VERSION(5, 1, 0), 0xEFF8372B, 0xEFF822A4, 0xF0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 37, 0), SYSTEM_VERSION(6, 0, 0), 0xEFF8372B, 0xEFF822A4, 0xF0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 38, 0), SYSTEM_VERSION(6, 1, 0), 0xEFF8372B, 0xEFF822A4, 0xF0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 39, 4), SYSTEM_VERSION(7, 0, 0), 0xEFF8372F, 0xEFF822A8, 0xF0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 40, 0), SYSTEM_VERSION(7, 2, 0), 0xEFF8372B, 0xEFF822A4, 0xF0000000, 0x20000000, 0x08000000 },
	// Old 3DS, new address layout
	{ false,  SYSTEM_VERSION(2, 44, 6), SYSTEM_VERSION(8, 0, 0), 0xDFF83837, 0xDFF82290, 0xE0000000, 0x20000000, 0x08000000 },
	{ false,  SYSTEM_VERSION(2, 46, 0), SYSTEM_VERSION(9, 0, 0), 0xDFF83837, 0xDFF82290, 0xE0000000, 0x20000000, 0x08000000 },
	// New 3DS
	{ true,   SYSTEM_VERSION(2, 44, 6), SYSTEM_VERSION(8, 0, 0), 0xDFF8382F, 0xDFF82260, 0xE0000000, 0x20000000, 0x10000000 }, // I don't think that this exists...
	// XXX: missing entry for New 3DS 8.1.0
	{ true,   SYSTEM_VERSION(2, 46, 0), SYSTEM_VERSION(9, 0, 0), 0xDFF8382F, 0xDFF82260, 0xE0000000, 0x20000000, 0x10000000 },
};

//------------------------------------------------------------------------------------------------
// Convert a user-mode virtual address in the linear heap into a kernel-mode virtual
// address using the version-specific information in this table entry.
void *KHAX::VersionData::ConvertLinearUserVAToKernelVA(void *address) const
{
	static_assert((std::numeric_limits<std::uintptr_t>::max)() == (std::numeric_limits<u32>::max)(),
		"you're sure that this is a 3DS?");

	// Need the pointer as an integer.
	u32 addr = reinterpret_cast<u32>(address);

	// Convert the address to a physical address, since that's how we know the mapping.
	u32 physical = osConvertVirtToPhys(addr);
	if (physical == 0)
	{
		return nullptr;
	}

	// Verify that the address is within FCRAM.
	if ((physical < m_fcramPhysicalAddress) || (physical - m_fcramPhysicalAddress >= m_fcramSize))
	{
		return nullptr;
	}

	// Now we can convert.
	return reinterpret_cast<char *>(m_fcramVirtualAddress) + (physical - m_fcramPhysicalAddress);
}

//------------------------------------------------------------------------------------------------
// Retrieve a VersionData for this kernel, or null if not recognized.
const KHAX::VersionData *KHAX::VersionData::GetForCurrentSystem()
{
	// Get kernel version for comparison.
	u32 kernelVersion = osGetKernelVersion();

	// Determine whether this is a New 3DS.
	bool isNew3DS;
	if (IsNew3DS(&isNew3DS, kernelVersion) != 0)
	{
		return nullptr;
	}

	// Search our list for a match.
	for (const VersionData *entry = s_versionTable; entry < &s_versionTable[KHAX_lengthof(s_versionTable)]; ++entry)
	{
		// New 3DS flag must match.
		if ((entry->m_new3DS && !isNew3DS) || (!entry->m_new3DS && isNew3DS))
		{
			continue;
		}
		// Kernel version must match.
		if (entry->m_kernelVersion != kernelVersion)
		{
			continue;
		}

		return entry;
	}

	return nullptr;
}


//------------------------------------------------------------------------------------------------
//
// Class MemChunkHax
//

//------------------------------------------------------------------------------------------------
// Basic initialization.
Result KHAX::MemChunkHax::Step1_Initialize()
{
	if (m_nextStep != 1)
	{
		KHAX_printf("MemChunkHax: Invalid step number %d for Step1_Initialize\n", m_nextStep);
		return MakeError(28, 5, KHAX_MODULE, 1016);
	}

	// Nothing to do in current implementation.
	++m_nextStep;
	return 0;
}

//------------------------------------------------------------------------------------------------
// Allocate linear memory for the memchunkhax operation.
Result KHAX::MemChunkHax::Step2_AllocateMemory()
{
	if (m_nextStep != 2)
	{
		KHAX_printf("MemChunkHax: Invalid step number %d for Step2_AllocateMemory\n", m_nextStep);
		return MakeError(28, 5, KHAX_MODULE, 1016);
	}

	// Allocate the linear memory for the overwrite process.
	u32 address = 0xFFFFFFFF;
	Result result = svcControlMemory(&address, 0, 0, sizeof(OverwriteMemory), MEMOP_ALLOC_LINEAR,
		static_cast<MemPerm>(MEMPERM_READ | MEMPERM_WRITE));

	KHAX_printf("Step2:res=%08lx addr=%08lx\n", result, address);

	if (result != 0)
	{
		return result;
	}

	m_overwriteMemory = reinterpret_cast<OverwriteMemory *>(address);
	m_overwriteAllocated = (1u << 6) - 1;  // all 6 pages allocated now

	// Why didn't we get a page-aligned address?!
	if (address & 0xFFF)
	{
		// Since we already assigned m_overwriteMemory, it'll get freed by our destructor.
		KHAX_printf("Step2:misaligned memory\n");
		return MakeError(26, 7, KHAX_MODULE, 1009);
	}

	// OK, we're good here.
	++m_nextStep;
	return 0;
}

//------------------------------------------------------------------------------------------------
// Free the second and fourth pages of the five.
Result KHAX::MemChunkHax::Step3_SurroundFree()
{
	if (m_nextStep != 3)
	{
		KHAX_printf("MemChunkHax: Invalid step number %d for Step3_AllocateMemory\n", m_nextStep);
		return MakeError(28, 5, KHAX_MODULE, 1016);
	}

	// We do this because the exploit involves triggering a heap coalesce.  We surround a heap
	// block (page) with two freed pages, then free the middle page.  By controlling both outside
	// pages, we know their addresses, and can fix up the corrupted heap afterward.
	//
	// Here's what the heap will look like after step 3:
	//
	// ___XX-X-X___
	//
	// _ = unknown (could be allocated and owned by other code)
	// X = allocated
	// - = allocated then freed by us
	//
	// In step 4, we will free the second page:
	//
	// ___X--X-X___
	//
	// Heap coalescing will trigger due to two adjacent free blocks existing.  The fifth page's
	// "previous" pointer will be set to point to the second page rather than the third.  We will
	// use gspwn to make that overwrite kernel code instead.
	//
	// We have 6 pages to ensure that we have surrounding allocated pages, giving us a little
	// sandbox to play in.  In particular, we can use this design to determine the address of the
	// next block--by controlling the location of the next block.
	u32 dummy;

	// Free the third page.
	if (Result result = svcControlMemory(&dummy, reinterpret_cast<u32>(&m_overwriteMemory->m_pages[2]), 0,
		sizeof(m_overwriteMemory->m_pages[2]), MEMOP_FREE, static_cast<MemPerm>(0)))
	{
		return result;
	}
	m_overwriteAllocated &= ~(1u << 2);

	// Free the fifth page.
	if (Result result = svcControlMemory(&dummy, reinterpret_cast<u32>(&m_overwriteMemory->m_pages[4]), 0,
		sizeof(m_overwriteMemory->m_pages[4]), MEMOP_FREE, static_cast<MemPerm>(0)))
	{
		return result;
	}
	m_overwriteAllocated &= ~(1u << 4);

	// Done.
	++m_nextStep;
	return 0;
}

//------------------------------------------------------------------------------------------------
// Free memory and such.
KHAX::MemChunkHax::~MemChunkHax()
{
	// This function has to be careful not to crash trying to shut down after an aborted attempt.
	if (m_overwriteMemory)
	{
		u32 dummy;

		// Each page has a flag indicating that it is still allocated.
		for (unsigned x = 0; x < KHAX_lengthof(m_overwriteMemory->m_pages); ++x)
		{
			// Don't free a page unless it remains allocated.
			if (m_overwriteAllocated & (1u << x))
			{
				Result res = svcControlMemory(&dummy, reinterpret_cast<u32>(&m_overwriteMemory->m_pages[x]), 0,
					sizeof(m_overwriteMemory->m_pages[x]), MEMOP_FREE, static_cast<MemPerm>(0));
				KHAX_printf("free %u: %08lx\n", x, res);
			}
		}
	}
}


//------------------------------------------------------------------------------------------------
//
// Miscellaneous
//

//------------------------------------------------------------------------------------------------
// Make an error code
inline Result KHAX::MakeError(Result level, Result summary, Result module, Result error)
{
	return (level << 27) + (summary << 21) + (module << 10) + error;
}

//------------------------------------------------------------------------------------------------
// Check whether this system is a New 3DS.
Result KHAX::IsNew3DS(bool *answer, u32 kernelVersionAlreadyKnown)
{
	// If the kernel version isn't already known by the caller, find out.
	u32 kernelVersion = kernelVersionAlreadyKnown;
	if (kernelVersion == 0)
	{
		kernelVersion = osGetKernelVersion();
	}

	// APT_CheckNew3DS doesn't work on < 8.0.0, but neither do such New 3DS's exist.
	if (kernelVersion >= SYSTEM_VERSION(2, 44, 6))
	{
		// Check whether the system is a New 3DS.  If this fails, abort, because being wrong would
		// crash the system.
		u8 isNew3DS = 0;
		if (Result error = APT_CheckNew3DS(nullptr, &isNew3DS))
		{
			*answer = false;
			return error;
		}

		// Use the result of APT_CheckNew3DS.
		*answer = isNew3DS != 0;
		return 0;
	}

	// Kernel is older than 8.0.0, so we logically conclude that this cannot be a New 3DS.
	*answer = false;
	return 0;
}

//------------------------------------------------------------------------------------------------
// Simple gspwn copy, not using any fancy looping.
Result KHAX::SimpleGSPwn(void *dest, const void *src, std::size_t size, s64 waitNanoseconds)
{
	// This is some black magic that I don't totally understand.
	GSPGPU_FlushDataCache(nullptr, static_cast<u8 *>(const_cast<void *>(src)), size);
	Result result = GX_SetTextureCopy(nullptr, static_cast<u32 *>(const_cast<void *>(src)), 0,
		static_cast<u32 *>(dest), 0, size, 8);

	// Yay for arbitrary delays.
	svcSleepThread(waitNanoseconds);

	return result;
}

//------------------------------------------------------------------------------------------------
extern "C" Result khaxInit()
{
	using namespace KHAX;

#ifdef KHAX_DEBUG
	bool isNew3DS;
	IsNew3DS(&isNew3DS, 0);
	KHAX_printf("khaxInit: k=%08lx f=%08lx n=%d\n", osGetKernelVersion(), osGetFirmVersion(),
		isNew3DS);
#endif

	// Look up the current system's version in our table.
	const VersionData *versionData = VersionData::GetForCurrentSystem();
	if (!versionData)
	{
		KHAX_printf("khaxInit: Unknown kernel version\n");
		return MakeError(27, 6, KHAX_MODULE, 39);
	}

	KHAX_printf("verdat t=%08lx s=%08lx v=%08lx\n", versionData->m_threadPatchAddress,
		versionData->m_syscallPatchAddress, versionData->m_fcramVirtualAddress);

	// Create the hack object.
	MemChunkHax hax{ versionData };

	// Run through the steps.
	if (Result result = hax.Step1_Initialize())
	{
		KHAX_printf("khaxInit: Step1 failed: %08lx\n", result);
		return result;
	}
	if (Result result = hax.Step2_AllocateMemory())
	{
		KHAX_printf("khaxInit: Step2 failed: %08lx\n", result);
		return result;
	}
	if (Result result = hax.Step3_SurroundFree())
	{
		KHAX_printf("khaxInit: Step3 failed: %08lx\n", result);
		return result;
	}

	KHAX_printf("khaxInit: end of implementation\n");
	return MakeError(27, 6, KHAX_MODULE, 1012);
}
