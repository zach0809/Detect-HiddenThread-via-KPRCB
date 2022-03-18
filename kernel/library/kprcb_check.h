#pragma once

#define ThreadListHead 0x5E0 // EPROCESS::ThreadListHead
#define ThreadListEntryK 0x2F8 // KTHREAD::ThreadListEntry

void hidden_system_threads_detect()
{	
	PKPRCB_META prcb = KeGetCurrentPrcb();
	PKTHREAD current_thread = prcb->CurrentThread;
	LIST_ENTRY* thread_list_entry = (LIST_ENTRY*)make_ptr(current_thread, ThreadListEntryK);
	PLIST_ENTRY list_entry = thread_list_entry;

	while ((list_entry = list_entry->Flink) != thread_list_entry)
	{
		PKTHREAD_META entry = CONTAINING_RECORD(list_entry, KTHREAD_META, ThreadListEntry);
		ULONG current_tid = reinterpret_cast<ULONG>(PsGetThreadId((PETHREAD)entry));
		uintptr_t current_startaddress = (uintptr_t)(((PETHREAD_META)entry)->StartAddress);

		if (current_tid != 0)
		{
			PETHREAD p_thread = 0;
			PsLookupThreadByThreadId(reinterpret_cast<HANDLE>(current_tid), &p_thread);
			
			//Removed from the PspCidTable completely
			if (p_thread == 0){
				DbgPrintEx(0, 0, "[PspCidTable] hidden thread id -> %d\n", current_tid);
			}else{
				//Get the thread id of the thread returned.
				ULONG ret_tid = reinterpret_cast<ULONG>(PsGetThreadID(p_thread));
				
				//Get the start address of the thread returned.
				uintptr_t ret_start_address = (uintptr_t)(((PETHREAD_META)p_thread)->StartAddress);

				//Check for swapped PspCidTable entry
				if(ret_tid!=current_tid)
					DbgPrintEx(0, 0, "[PspCidTable] A KTHREAD found via the KPRCB has a tid of %d but the tid of the cid table entry for this thread is %d!\n", current_tid, ret_tid);

				//Validate the IsSystemThread flag for the entry in the PspCidTable
				if(PsIsSystemThread(p_thread) != PsIsSystemThread((PETHREAD)entry))
					DbgPrintEx(0, 0, "[PspCidTable] IsSystemThread is spoofed for tid of %d\n", current_tid);
				
				//Validate start addresses
				if(ret_start_address!=current_startaddress)
					DbgPrintEx(0, 0, "[PspCidTable] A KTHREAD found via the KPRCB has a start address of %llx but the corresponding cid table entry start address is %llx!\n", current_startaddress, ret_start_address);
			}	
		}
	}
}
