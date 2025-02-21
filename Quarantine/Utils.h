#include <ntifs.h>

#pragma warning(disable: 4995)
#pragma warning(disable: 4996)

/// <summary>
/// ERESOURCE Wrapper to provide read write lock 
/// </summary>
typedef struct _EXECUTIVE_RESOURCE
{
	ERESOURCE m_Lock;

	VOID Init()
	{
		ExInitializeResource(&m_Lock);
	}

	VOID Delete()
	{
		ExDeleteResource(&m_Lock);
	}

	VOID Lock()
	{
		ExEnterCriticalRegionAndAcquireResourceExclusive(&m_Lock);
	}

	VOID Unlock()
	{
		ExReleaseResourceAndLeaveCriticalRegion(&m_Lock);
	}

	VOID LockShared()
	{
		ExEnterCriticalRegionAndAcquireResourceShared(&m_Lock);
	}

	VOID UnlockShared()
	{
		Unlock();
	}

}EXECUTIVE_RESOURCE, *PEXECUTIVE_RESOURCE;