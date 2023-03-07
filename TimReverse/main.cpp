#include <Windows.h>
#include <iostream>
#include "utils.h"


int main()
{
	uint32_t pid = utils::get_process_id("QQ.exe");
	if (!pid) {
		std::cout << "[-] 找不到QQ进程" << std::endl;
		pid = utils::get_process_id("TIM.exe");
		if (!pid) {
			std::cout << "[-] 找不到TIM进程" << std::endl;
			return 0;
		}
		else {
			std::cout << "[+] 找到TIM进程pid=" << std::dec << pid << std::endl;
		}
	}
	else {
		std::cout << "[+] 找到QQ进程pid=" << pid << std::endl;
	}

	uintptr_t base_SNSApp = utils::get_module_base(pid, "SNSApp.dll");

	uintptr_t time_interval_addr = utils::find_pattern_process(pid, base_SNSApp, 0x10000, "FF 15 ? ? ? ? 2B 47 14 B9 ? ? ? ? 3B C8 1B C0 F7 D8") + 10;
	if (time_interval_addr < 16) {
		std::cout << "[-] 定位时间间隔校验地址失败" << std::endl;
		return 0;
	}
	else {
		std::cout << "[+] 定位到时间校验地址0x" << std::hex << time_interval_addr << std::endl;

		uint32_t time_interval = utils::read<uint32_t>(pid, time_interval_addr);

		std::cout << "[+] 当前抖窗时间间隔" << std::dec << time_interval << "ms" << std::endl;

		if (utils::protect_process_memory(pid, time_interval_addr, 4, PAGE_EXECUTE_READWRITE) && utils::write<uint32_t>(pid, time_interval_addr, 0)) {

			std::cout << "[+] Patch成功" << std::endl;

			uint32_t val = utils::read<uint32_t>(pid, time_interval_addr);
			std::cout << "[+] 当前抖窗时间间隔" << std::dec << val << "ms" << std::endl;
		}
		else {
			std::cout << "[-] 写入失败" << GetLastError() << std::endl;
		}
	}
	
	uintptr_t base_IM = utils::get_module_base(pid, "IM.dll");
	uintptr_t recall_private_je_addr = utils::find_pattern_process(pid, base_IM + 0x60000, 0x10000, "0F 85 ? ? ? ? 81 7D ? ? ? ? ? 74 0D 81 7D ? ? ? ? ? 0F 85") + 13;
	if (recall_private_je_addr < 16) {
		std::cout << "[-] 定位私聊消息撤回地址失败" << std::endl;
		return 0;
	}
	else {
		std::cout << "[+] 定位到私聊消息撤回地址0x" << std::hex << recall_private_je_addr << std::endl;
		if (utils::protect_process_memory(pid, recall_private_je_addr, 2, PAGE_EXECUTE_READWRITE) && utils::write<uint16_t>(pid, recall_private_je_addr, 0x9090)) {
			std::cout << "[+] Patch成功" << std::endl;
		}
		else {
			std::cout << "[-] 写入失败" << GetLastError() << std::endl;
		}
	}

	uintptr_t recall_group_je_addr = utils::find_pattern_process(pid, base_IM + 0x60000, 0x10000, "B8 ? ? ? ? 66 3B F0 0F 85 ? ? ? ? 80 7D FF 11 0F 85") + 1;
	if (recall_group_je_addr < 16) {
		std::cout << "[-] 定位群聊消息撤回地址失败" << std::endl;
		return 0;
	}
	else {
		std::cout << "[+] 定位到群聊消息撤回地址0x" << std::hex << recall_group_je_addr << std::endl;
		if (utils::protect_process_memory(pid, recall_group_je_addr, 4, PAGE_EXECUTE_READWRITE) && utils::write<uint32_t>(pid, recall_group_je_addr, 0)) {
			std::cout << "[+] Patch成功" << std::endl;
		}
		else {
			std::cout << "[-] 写入失败" << GetLastError() << std::endl;
		}
	}

	getchar();
	return 0;
}
