from idaapi import *


class Excercise9_plugin_t(plugin_t):
    # five required fields for all plugins
    flags = 0
    wanted_name = 'Exercise9 Python plugin'
    wanted_hotkey = 'Alt-8'
    comment = ''
    help = ''

    # called by Ida at initial plugin load
    # return PLUGIN_SKIP and Ida will not activate the plugin
    # return PLUGIN_OK or PLUGIN_KEEP and Ida will list the
    #  plugin under Edit/Plugins and activate the plugin when
    #  the hot-key sequence is pressed
    def init(self):
        # msg prints to Ida's output window
        msg('Exercise9 Python plugin init called.\n')
        return PLUGIN_OK

    # called when the plugin is being unloaded, generally in
    # conjunction with closing a database
    def term(self):
        # msg prints to Ida's output window
        msg('Exercise9 Python plugin term called.\n')

    # called when the hot-key sequence is pressed IF PLUGIN_KEEP
    # or PLUGIN_OK was returned by init()
    def run(self, arg):
        # warning opens a modal dialog box
        # warning('Exercise9 Python plugin run(%d) called.\n' % arg)

        search_bytes = askstr(HIST_SRCH, None, 'Enter string of hex bytes')
        result = 0
        while True:
            result = find_binary(result, 0xFFFFFFFF, search_bytes, 16, SEARCH_DOWN | SEARCH_NEXT)
            if result == BADADDR:
                break

            print(hex(result))
            result += 1




# required entry point function to instantiate your plugin object
def PLUGIN_ENTRY():
    return Excercise9_plugin_t()
