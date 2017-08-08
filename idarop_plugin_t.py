# IDA libraries
import idaapi
from idaapi import plugin_t

from idarop import IDAROP_VERSION, IDAROP_DESCRIPTION
from idarop.ui import IdaRopManager

class idarop_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = IDAROP_DESCRIPTION
    help = IDAROP_DESCRIPTION
    wanted_name = "IDA ROP"
    wanted_hotkey = ""

    def init(self):
        """ On script initalisation : load previous rop results and init menu items """

        # Only Intel x86/x86-64 are supported
        if idaapi.ph_get_id() == idaapi.PLFM_386:

            global idarop_manager

            # Check if already initialized
            if not 'idarop_manager' in globals():

                idarop_manager = IdaRopManager()
                if idarop_manager.add_menu_items():
                    print("[IdaRop] Failed to initialize IDA Sploiter.")
                    idarop_manager.del_menu_items()
                    del idarop_manager
                    return idaapi.PLUGIN_SKIP
                else:
                    try:
                        idarop_manager.load_internal_db()
                    except Exception as e:
                        pass

                    print("[IdaRop] IDA ROP View  v%s initialized " % IDAROP_VERSION)

            return idaapi.PLUGIN_KEEP
        else:
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        """ On IDA's close event, export the Rop gadget list in a default csv file"""
        idaapi.show_wait_box("Saving gadgets ...")
        try:
            idarop_manager.save_internal_db()
        except Exception as e:
            pass
        idaapi.hide_wait_box()

def PLUGIN_ENTRY():
    return idarop_t()

###############################################################################
# Script / Testing
###############################################################################

def idarop_main():
    global idarop_manager

    if 'idarop_manager' in globals():
        idarop_manager.del_menu_items()
        del idarop_manager

    idarop_manager = IdaRopManager()
    idarop_manager.add_menu_items()

    idarop = idarop_manager.idarop

if __name__ == '__main__':
    #idarop_main()
    pass