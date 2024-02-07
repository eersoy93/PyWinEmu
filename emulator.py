from unicorn import *
from unicorn.x86_const import *

import colorama

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
            self.cpu_emulator.emu_start(entry_point, entry_point + exe_code_size)
        except UcError as e:
            colorama.init()
            print(colorama.Fore.RED + "ERROR: " + colorama.Fore.RESET + f"{e}")
            return Emulator.EXIT_FAILURE
        else:
            self.cpu_emulator.emu_stop()

            self.cpu_emulator.close()

            return Emulator.EXIT_SUCCESS
