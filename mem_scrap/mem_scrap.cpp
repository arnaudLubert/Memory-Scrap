#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

void searchVariableFromModules(HANDLE &, HMODULE &, std::vector<LPVOID> &, int &);
void searchForVariablesEveryWhere(HANDLE &, std::vector<LPVOID> &, int &);

int main(int ac, char **av)
{
	int target;

	if (ac < 3) {
		std::cerr << "USAGE: mem_scrap [program_name] [value]" << std::endl;
		return 1;
	}

	try {
		target = stoi(std::string(av[2]), 0, 10);
	}
	catch (const std::invalid_argument& e) {
		std::cerr << "Error while parsing: " << e.what() << std::endl;
		return 1;
	}
	catch (const std::out_of_range& e) {
		std::cerr << "Error while parsing: " << e.what() << std::endl;
		return 1;
	}

	// get pid
	DWORD pid;
	HWND program = FindWindowA(0, av[1]);

	if (!program) {
		std::cerr << "Program not found." << std::endl;
		return 1;
	}

	GetWindowThreadProcessId(program, &pid);
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid); // also PROCESS_VM_WRITE to write

	std::vector<LPVOID> variables;
	searchForVariablesEveryWhere(process, variables, target);

	UINT32 value = 0;
	while (variables.size() > 1 && target != 0) {

		// filter
		for (std::vector<LPVOID>::iterator it = variables.begin(); it != variables.end(); ) {
			if (ReadProcessMemory(process, *it, &value, sizeof(UINT32), 0) == 0)
				break;

			if (value != target)
				it = variables.erase(it);
			else
				it++;
		}

		std::cout << variables.size() << " matche(s)" << std::endl;

		if (variables.size() == 0)
			return 0;
		else if (variables.size() == 1) {
			std::cout << "Variable is at address: 0x" << variables.at(0) << std::endl;
			return 0;
		}

		std::cout << "Type a number: (0 to stop)" << std::endl;
		std::cin >> target;
	}

	for (auto variable : variables)
		std::cout << "0x" << variable << std::endl;

	return 0;
}

void searchVariableFromModules(HANDLE &process, HMODULE &_module, std::vector<LPVOID> &variables, int &target) {

	MODULEINFO moduleInfo;
	if (GetModuleInformation(process, _module, (LPMODULEINFO)&moduleInfo, sizeof(MODULEINFO)) == 0) {
		std::cerr << "Error on GetModuleInformation()" << std::endl;
		return;
	}
	LPVOID baseAddress = moduleInfo.lpBaseOfDll; // get base address of process
	SIZE_T stopAddress = (SIZE_T)baseAddress + moduleInfo.SizeOfImage; // get max address of module
	std::cout << "from 0x" << baseAddress << " to 0x" << (LPVOID)stopAddress << std::endl;

	// search for variables
	UINT32 value = 0;
	char *tab = new char[moduleInfo.SizeOfImage];

	if (ReadProcessMemory(process, baseAddress, &tab[0], moduleInfo.SizeOfImage, 0) == 0) {
		std::cout << "Read failed." << std::endl;
		delete[] tab;
		return;
	}

	//for (int i = 0; i < moduleInfo.SizeOfImage - sizeof(UINT32); i++) {
	for (int i = 0; i < moduleInfo.SizeOfImage; i += sizeof(UINT32)) {
		if (*((UINT32 *)&tab[i]) == target) {
			variables.push_back((LPVOID)((UINT64)baseAddress + i));
		}
	}

	delete[] tab;
}

// search through all physical memory addresses
void searchForVariablesEveryWhere(HANDLE &process, std::vector<LPVOID> &variables, int &target) {
	SYSTEM_INFO si;
	UINT64 max, addr = 0;

	GetSystemInfo(&si);
	SIZE_T pageSize = si.dwPageSize * 1000;

	max = 0x7FFFFFFF - pageSize;
	char *tab = new char[pageSize];

	while (addr < max) {
		if (ReadProcessMemory(process, (LPVOID)addr, &tab[0], pageSize, 0))
			for (int i = 0; i < pageSize; i += sizeof(UINT32))
				if (*((UINT32 *)&tab[i]) == target)
					variables.push_back((LPVOID)(addr + i));

		addr += pageSize;
	}

	delete[] tab;
}
