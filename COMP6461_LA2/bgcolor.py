
class BgColor:
    ENDC = '\033[0m'
    DEFAULT = '\033[99m'
    BLUE = '\033[94m'
    GREY = '\033[90m'
    YELLOW = '\033[93m'
    BLACK = '\033[90m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RED = '\033[91m'

    @staticmethod
    def color_blue_wrapper(string):
        return BgColor.BLUE + string + BgColor.ENDC

    @staticmethod
    def color_default_wrapper(string):
        return BgColor.DEFAULT + string + BgColor.ENDC

    @staticmethod
    def color_grey_wrapper(string):
        return BgColor.GREY + string + BgColor.ENDC

    @staticmethod
    def color_yellow_wrapper(string):
        return BgColor.YELLOW + string + BgColor.ENDC

    @staticmethod
    def color_black_wrapper(string):
        return BgColor.BLACK + string + BgColor.ENDC

    @staticmethod
    def color_cyan_wrapper(string):
        return BgColor.CYAN + string + BgColor.ENDC

    @staticmethod
    def color_green_wrapper(string):
        return BgColor.GREEN + string + BgColor.ENDC

    @staticmethod
    def color_magenta_wrapper(string):
        return BgColor.MAGENTA + string + BgColor.ENDC

    @staticmethod
    def color_white_wrapper(string):
        return BgColor.WHITE + string + BgColor.ENDC

    @staticmethod
    def color_red_wrapper(string):
        return BgColor.RED + string + BgColor.ENDC
