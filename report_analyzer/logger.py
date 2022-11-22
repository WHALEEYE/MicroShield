from enum import Enum


class Mode(Enum):
    DEBUG = 1
    INFO = 2
    QUIET = 3


class Logger:
    def __init__(self, mode):
        self.mode = mode

    def info(self, info):
        if self.mode.value <= Mode.INFO.value:
            print(f"\033[34m[INFO]  {info}\033[0m")

    def debug(self, info):
        if self.mode == Mode.DEBUG:
            print(f"\033[35m[DEBUG] {info}\033[0m")
