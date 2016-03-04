from idaapi import *


class empty_plugin_t(plugin_t):
    # five required fields for all plugins
    flags = 0
    wanted_name = 'Empty Python Plugin'
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
        msg('Empty Python plugin init called.\n')
        return PLUGIN_OK

    # called when the plugin is being unloaded, generally in
    # conjunction with closing a database
    def term(self):
        # msg prints to Ida's output window
        msg('Empty Python plugin term called.\n')

    # called when the hot-key sequence is pressed IF PLUGIN_KEEP
    # or PLUGIN_OK was returned by init()
    def run(self, arg):
        # warning opens a modal dialog box
        warning('Empty Python plugin run(%d) called.\n' % arg)


# required entry point function to instantiate your plugin object
def PLUGIN_ENTRY():
    return empty_plugin_t()
