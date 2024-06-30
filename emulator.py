from unicorn import *
from unicorn.x86_const import *

import colorama

from dlls.kernel32 import Kernel32  # Local package!!!

class Emulator:
    EXIT_SUCCESS = 0
    EXIT_FAILURE = 1
    def __init__(self, image, image_base, base_relocation, base_relocation_size, total_memory_size):
        self.memory_image = image
        self.image_base = image_base
        self.base_relocation = base_relocation
        self.base_relocation_size = base_relocation_size
        self.total_memory_size = total_memory_size

        self.cpu_emulator = Uc(UC_ARCH_X86, UC_MODE_32)
        self.cpu_emulator.mem_map(self.image_base, self.total_memory_size)
        self.cpu_emulator.mem_write(self.image_base, self.memory_image)

    def emulate(self, entry_point, exe_code_size):
        try:
            if not self.get_emulator_win_version_is_nt():
                print(colorama.Fore.YELLOW + "WARNING: " + colorama.Fore.RESET + "The emulation is NOT as" + colorama.Fore.CYAN + " Windows NT" + colorama.Fore.RESET + "!!!")

            print("Emulation as: " + colorama.Fore.CYAN + f"{self.get_emulator_win_version_str()}" + colorama.Fore.RESET)

            self.cpu_emulator.emu_start(entry_point, entry_point + exe_code_size)
        except UcError as e:
            colorama.init()
            print(colorama.Fore.RED + "ERROR: " + colorama.Fore.RESET + f"{e}")
            return Emulator.EXIT_FAILURE
        else:
            self.cpu_emulator.emu_stop()

            self.cpu_emulator.close()

            return Emulator.EXIT_SUCCESS
    
    def get_emulator_win_version_is_nt(self):
        ver = Kernel32.GetVersion()

        if ver < 0x80000000:
            return True
        else:
            return False

    def get_emulator_win_version_str(self):
        ver = Kernel32.GetVersion()
        ver_major = ver >> 24 & 0xFF
        ver_minor = ver >> 16 & 0xFF
        ver_build = 0x0000
        ver_str = ""

        if ver < 0x80000000:
            ver_build = ver & 0xFFFF
            ver_str = "Windows NT"
        elif ver_major < 4:
            ver_build = (ver & 0xFFFF) & ~0x8000
            ver_str = "Win32s"
        else:
            ver_build = ver & 0xFFFF
            ver_str = "Windows 95"

        return ver_str
