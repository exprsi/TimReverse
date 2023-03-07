#pragma once
#include <stdint.h>

namespace utils
{
	uintptr_t get_module_base(uint32_t pid, const char* module_name);

	uint32_t get_process_id(const char* process_name);

	uintptr_t find_pattern(uintptr_t base, size_t size, const char* pattern);

	uintptr_t find_pattern_process(uint32_t pid, uintptr_t base, size_t size, const char* pattern);

	bool read_process_memory(uint32_t pid, uintptr_t addr, void* buffer, size_t size);

	bool write_process_memory(uint32_t pid, uintptr_t addr, void* buffer, size_t size);

	bool protect_process_memory(uint32_t pid, uintptr_t addr, size_t size, uint32_t prot);

	template <class T>
	T read(uint32_t pid, uintptr_t addr)
	{
		T buf;
		read_process_memory(pid, addr, &buf, sizeof(T));
		return buf;
	}

	template <class T>
	bool write(uint32_t pid, uintptr_t addr, T buffer)
	{
		return write_process_memory(pid, addr, &buffer, sizeof(T));
	}
};

