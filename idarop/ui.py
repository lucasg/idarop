""" IDA ROP view plugin UI functions and classes """

# IDA libraries
import idaapi
import idc
from idaapi import Form, Choose2

# IDA plugin
try :
    import netnode
    netnode_package = True
except ImportError as ie:
    netnode_package =  False
    


# Python libraries
import os
import csv

from .engine import IdaRopEngine, IdaRopSearch, Gadget


class IdaRopForm(Form):
    """ Ida Rop Search input form """

    def __init__(self, idaropengine,  select_list = None):

        self.engine = idaropengine
        self.select_list = select_list

        self.segments = SegmentView(self.engine, embedded=True)

        Form.__init__(self, 
r"""BUTTON YES* Search
Search ROP gadgets

{FormChangeCb}<Segments:{cEChooser}>

<Bad Chars        :{strBadChars}>     
Unicode Table    <ANSI:{rUnicodeANSI}><OEM:{rUnicodeOEM}><UTF7:{rUnicodeUTF7}><UTF8:{rUnicodeUTF8}>{radUnicode}>
<Bad Instructions :{strBadMnems}>
<Max gadget size  :{intMaxRopSize}>     Other settings :
<Max gadget offset:{intMaxRopOffset}>          <Allow conditional jumps:{cRopAllowJcc}>
<Max RETN imm16   :{intMaxRetnImm}>            <Do not allow bad bytes:{cRopNoBadBytes}>
<Max JOP imm8/32  :{intMaxJopImm}>             <Search for ROP gadgets:{cRopSearch}>
<Max gadgets      :{intMaxRops}>               <Search for JOP gadgets:{cJopSearch}>{ropGroup}>
 
""", {
                'cEChooser'       : Form.EmbeddedChooserControl(self.segments, swidth=110),
                'ropGroup'        : Form.ChkGroupControl(('cRopAllowJcc','cRopNoBadBytes','cRopSearch','cJopSearch')),
                'intMaxRopSize'   : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=self.engine.rop.maxRopSize),
                'intMaxRopOffset' : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=self.engine.rop.maxRopOffset),
                'intMaxRops'      : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=self.engine.rop.maxRops),
                'intMaxRetnImm'   : Form.NumericInput(swidth=4,tp=Form.FT_HEX,value=self.engine.rop.maxRetnImm),
                'intMaxJopImm'    : Form.NumericInput(swidth=4,tp=Form.FT_HEX,value=self.engine.rop.maxJopImm),
                'strBadChars'     : Form.StringInput(swidth=92,tp=Form.FT_ASCII),
                'radUnicode'      : Form.RadGroupControl(("rUnicodeANSI","rUnicodeOEM","rUnicodeUTF7","rUnicodeUTF8")),
                'strBadMnems'     : Form.StringInput(swidth=92,tp=Form.FT_ASCII,value="leave, int, into, enter, syscall, sysenter, sysexit, sysret, in, out, loop, loope, loopne, lock, rep, repe, repz, repne, repnz"),
                'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.cEChooser)

            # Preselect executable segments on startup if none were already specified:
            if self.select_list == None:

                self.select_list = list()

                for i, seg in enumerate(self.engine.segments):
                    if seg.x:
                        self.select_list.append(i)

            self.SetControlValue(self.cEChooser, self.select_list)

            # Enable both ROP and JOP search by default
            self.SetControlValue(self.cRopSearch, True)
            self.SetControlValue(self.cJopSearch, True)

            # Skip bad instructions by default
            self.SetControlValue(self.cRopNoBadBytes, True)

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

###############################################################################
class SegmentView(Choose2):

    def __init__(self, idarop, embedded = False):
        self.idarop = idarop

        Choose2.__init__(self, "Segments",
                         [ ["Name",   13 | Choose2.CHCOL_PLAIN],
                           ["Start",  13 | Choose2.CHCOL_HEX], 
                           ["End",    10 | Choose2.CHCOL_HEX], 
                           ["Size",   10 | Choose2.CHCOL_HEX],
                           ["R",       1 | Choose2.CHCOL_PLAIN],
                           ["W",       1 | Choose2.CHCOL_PLAIN], 
                           ["X",       1 | Choose2.CHCOL_PLAIN],
                           ["Class",   8 | Choose2.CHCOL_PLAIN], 
                         ],
                         flags = Choose2.CH_MULTI,  # Select multiple modules
                         embedded=embedded)

        self.icon = 150

        # Items for display
        self.items = list()

        # Initialize/Refresh the view
        self.refreshitems()

        # Selected items
        self.select_list = list()

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

    def refreshitems(self):
        self.items = list()

        for segment in self.idarop.list_segments():
            self.items.append(segment.get_display_list())

    def OnCommand(self, n, cmd_id):

        # Search ROP gadgets
        if cmd_id == self.cmd_search_gadgets:
            
            # Initialize ROP gadget form with empty selection
            self.idarop.process_rop(select_list = self.select_list)

    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):

        if not len(self.items) > 0:
            return -1

        segment = self.idarop.list_segments()[n]
        if segment.x : # Exec Seg
            return 61
        else:
            return 59

    def OnClose(self):
        self.cmd_search_gadgets = None

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()


class IdaRopView(Choose2):
    """
    Chooser class to display security characteristics of loaded modules.
    """
    def __init__(self, idarop):

        self.idarop = idarop

        Choose2.__init__(self,
                         "ROP gadgets",
                         [ ["Segment",           13 | Choose2.CHCOL_PLAIN],
                           ["Address",           13 | Choose2.CHCOL_HEX],
                           ["Return Address",    13 | Choose2.CHCOL_HEX], 
                           ["Gadget",            30 | Choose2.CHCOL_PLAIN], 
                           ["Opcodes",           20 | Choose2.CHCOL_PLAIN],
                           ["Size",               3 | Choose2.CHCOL_DEC],
                           ["Pivot",              4 | Choose2.CHCOL_DEC],
                         ],
                         flags = Choose2.CH_MULTI)

        self.icon = 182

        # Items for display
        self.items = []

        # rop list cache for instantaneous loading if there has not been any new data
        self.rop_list_cache = None

        # Initialize/Refresh the view
        self.refreshitems()

        # export as csv command
        self.cmd_export_csv  = None

        # clear result command
        self.clear_rop_list = None

        

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        if self.cmd_export_csv == None:
            self.cmd_export_csv  = self.AddCommand("Export as csv...", flags = idaapi.CHOOSER_POPUP_MENU, icon=40)
        if self.clear_rop_list == None:
            self.clear_rop_list  = self.AddCommand("Clear rop list", flags = idaapi.CHOOSER_POPUP_MENU, icon=32)

        return True

    def refreshitems(self):

        # Pb : rop engine has not been init
        if self.idarop.rop == None:
            return 

        # No new data present
        if self.rop_list_cache == self.idarop.rop.gadgets:
            return

        self.items = []

        # No data present
        if len(self.idarop.rop.gadgets) == 0:
            return


        if len(self.idarop.rop.gadgets) > 10000:
            idaapi.show_wait_box("Ida rop : loading rop list ...")

        for i,g in enumerate(self.idarop.rop.gadgets):

            # reconstruct disas
            if g.opcodes == "":

                bad_gadget = False
                opcodes = idc.GetManyBytes(g.address, g.ret_address - g.address + 1)
                instructions = list()
                ea = g.address
                while ea <= g.ret_address:
                    instructions.append(idc.GetDisasmEx(ea, idaapi.GENDSM_FORCE_CODE))
                    ea += idaapi.decode_insn(ea) 

                    # Badly decoded gadget
                    if idaapi.decode_insn(ea) == 0:
                        bad_gadget = True
                        break


                if not bad_gadget:
                    h = Gadget(
                        address = g.address,
                        ret_address = g.ret_address,
                        instructions = instructions,
                        opcodes = opcodes,
                        size = len(opcodes)
                    )
                    self.idarop.rop.gadgets[i] = h

                    self.items.append(h.get_display_list(self.idarop.addr_format))
            else:
                self.items.append(g.get_display_list(self.idarop.addr_format))

        self.rop_list_cache = self.idarop.rop.gadgets
        if len(self.idarop.rop.gadgets) > 10000:
            idaapi.hide_wait_box()



    def OnCommand(self, n, cmd_id):

        # Export CSV
        if cmd_id == self.cmd_export_csv:

            file_name = idaapi.askfile_c(1, "*.csv", "Please enter CSV file name")
            if file_name:
                print ("[idarop] Exporting gadgets to %s" % file_name)
                with open(file_name, 'wb') as csvfile:
                    csvwriter = csv.writer(csvfile, delimiter=',',
                                            quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    csvwriter.writerow(["Address","Gadget","Size","Pivot"])
                    for item in self.items:
                        csvwriter.writerow(item)

        elif cmd_id == self.clear_rop_list:
            self.idarop.clear_rop_list()
            self.refreshitems()

        return 1

    def OnSelectLine(self, n):
        """ Callback on double click line : should open a custom view with the disas gadget.
            IDA disass view can't show "unaligned" gadgets.
        """
        idaapi.jumpto( self.idarop.rop.gadgets[n].address )

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        self.cmd_export_csv  = None
        self.clear_rop_list  = None

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()



class IdaRopManager():
    """ Top-level object managing IDA Rop View plugin """

    def __init__(self): 
 
        # Initialize ROP gadget search engine
        self.engine = IdaRopEngine()
        self.engine.rop = IdaRopSearch(self.engine)
        self.ropView = IdaRopView(self.engine)

        # Defered csv loading for a faster startup
        self.defered_loading = False

        # List of menu item added by the plugin
        self.addmenu_item_ctxs = list()

        # blob manager for saving internal db into idb file
        self.blob_manager = None
        if netnode_package :
            self.blob_manager = netnode.Netnode("$ idarop.rop_blob")
        else:
            print("[IdaRop] IdaRop rely on the Netnode package to save the rop database in the idb file.")
            print("         Since it's not present, the results will be discarded when closing IDA.")
    

    def add_menu_items(self):
        """ Init additions to Ida's menu entries """

        def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):
            """ helper for adding a menu item  """

            # add menu item and report on errors
            addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
            if addmenu_item_ctx is None:
                return 1
            else:
                self.addmenu_item_ctxs.append(addmenu_item_ctx)
                return 0

        if add_menu_item_helper(self, "Search/all error operands", "list rop gadgets...", "Ctrl+Shift+r", 1, self.proc_rop, None): return 1
        if add_menu_item_helper(self, "View/Open subviews/Problems", "View rop gadgets...", "Shift+r", 1, self.show_rop_view, None): return 1
        return 0

    
    def del_menu_items(self):
        """ Clear Ida Rop plugin menu entries """
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            idaapi.del_menu_item(addmenu_item_ctx)

    
    def show_rop_view(self):
        """ Show the list of rop gadgets found """

        # If the default csv exist but has not been loaded, load here
        if self.defered_loading == True:
            idaapi.show_wait_box("loading gadgets db ...")
            self.load_default_csv(force = True)
            idaapi.hide_wait_box()
            self.defered_loading = False

        # Show the ROP gadgets view
        self.ropView.refreshitems()
        self.ropView.show()

    def proc_rop(self):
        """ Search for rop gadgets, based on user input options """
        
        # Prompt user for ROP search settings
        f = IdaRopForm(self.engine)
        ok = f.Execute()
        if ok == 1:
            # reset previous results
            self.defered_loading = False

            ret = self.engine.process_rop(f, f.segments.GetEmbSelection())

            if ret:
                self.show_rop_view()

                # force redraw of every list views
                idaapi.refresh_lists()

        f.Free()


    def save_internal_db(self):
        """ store the found rop gadget in the default internal db """

        if len(self.engine.rop.gadgets) == 0 or self.blob_manager == None:
            return
        
        cancel_flag = False
        internal_repr = list()
        for item in self.engine.rop.gadgets:

                address,ret_addres = item.address, item.ret_address
                offset = "0x%x" % (address - idaapi.get_imagebase())
                ret_offset = "0x%x" % (ret_addres - idaapi.get_imagebase())

                internal_repr.append((offset, ret_offset))

                if idaapi.wasBreak():
                    cancel_flag = True
                    print("[IdaRop] save internal db interrupted.")
                    break

        # save only on success
        if not cancel_flag:
            txt_repr = ";".join( "%s:%s" % (g[0],g[1]) for g in internal_repr)
            self.blob_manager["db"] = txt_repr

    def load_internal_db(self, force=False):
        """ Load the rop gadgets list from the internal db """

        if self.blob_manager == None :
            return

        internal_repr =  self.blob_manager["db"].split(";")
        if internal_repr == None:
            return

        for item in internal_repr:
                offset,ret_offset = item.split(':')
                
                # Reconstruct linear address based on binary base address and offset
                address = int(offset, 16) + idaapi.get_imagebase()
                ret_address = int(ret_offset, 16) + idaapi.get_imagebase()

                gadget = Gadget(
                    address = address,
                    ret_address =  ret_address,
                    instructions = list(),
                    opcodes = "",
                    size = 0
                )

                self.engine.rop.gadgets.append(gadget)

                if idaapi.wasBreak():
                    print("[IdaRopLoad] Load csv file interrupted.")
                    break