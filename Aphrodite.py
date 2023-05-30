import ida_idaapi
import idaapi
import ida_hexrays
import ida_lines


class AphroditeHook(idaapi.Hexrays_Hooks):
    def __init__(self, *args):
        idaapi.Hexrays_Hooks.__init__(self, *args)
        self.log_tag = "AphroditeHook"
        self.DEBUG = 0
        self.collapsed_table = {}
        self.origin_code = {}
    
    def log(self, msg):
        if self.DEBUG==1:
            print("##{}: {}".format(self.log_tag,msg))
        return 0
    
    
    def regen_code(self, vu):
        new_code = vu.cfunc.get_pseudocode()
        line0 = new_code.at(0).line[:]
        new_code.clear()
        i = 0
        for c in self.collapsed_table[line0]:
            if i <= c[0]:
                for sl_line in self.origin_code[line0][i:c[0]+1]:
                    new_code.push_back(idaapi.simpleline_t(sl_line))
                offset_line = self.origin_code[line0][c[0]][:]
                offset_line = idaapi.tag_remove(offset_line)
                offset = offset_line.index(offset_line.lstrip()[0])
                new_code.push_back(idaapi.simpleline_t(offset*" " + "  ..."))
                i = c[1]
        for sl_line in self.origin_code[line0][i:]: 
            new_code.push_back(idaapi.simpleline_t(sl_line))
        place = idaapi.get_custom_viewer_place(vu.ct, False)[0]
        place.lnnum = 0
        idaapi.refresh_idaview_anyway()

    def find_block(self, ocode, cur_lnnum, offset):
        for i in range(cur_lnnum+1, len(ocode)):
            cur_line = ocode[i]
            cur_line = ida_lines.tag_remove(ocode[i])
            try:
                cur_offset = cur_line.index(cur_line.lstrip()[0])
            except IndexError:
                continue
            # skip label
            if cur_offset == 0:
                continue
            if cur_offset <= offset:
                return i

    def abs_lnnum(self, line0, lnnum):
        self.log('get abs_lnnum @ {}'.format(lnnum))
        last_end = 0
        for c in self.collapsed_table[line0]:
            self.log('abs_lnnum test lnnum:{} c[0]:{}, c[1]:{}, last_end:{}'.format(lnnum, c[0], c[1], last_end))
            if c[0] < lnnum and c[0] >= last_end:
                lnnum += c[1] - c[0] - 2
                self.log('abs_lnnum after add {}'.format(lnnum))
            last_end = c[1] if c[1] > last_end else last_end
        return lnnum


    def collapse(self, vu, ccode, line_code, cur_lnnum):
        self.log('cur_lnnum: {}'.format(cur_lnnum))
        _i = line_code.index(line_code.lstrip()[0])
        line0 = ccode.at(0).line[:]
        if line0 not in self.collapsed_table:
            self.collapsed_table[line0] = []
        if line0 not in self.origin_code:
            self.origin_code[line0] = [sl.line for sl in ccode]
        abs_lnnum = self.abs_lnnum(line0, cur_lnnum)
        end_lnnum = self.find_block(self.origin_code[line0], abs_lnnum, _i)
        self.log('abs_lnnum:{}, end_lnnum:{}'.format(abs_lnnum, end_lnnum))
        if end_lnnum - abs_lnnum <= 1:
            return
        
        for c in self.collapsed_table[line0]:
            if c[0] == abs_lnnum:
                self.collapsed_table[line0].remove((abs_lnnum, end_lnnum))
                self.regen_code(vu)
                break
        else:
            self.collapsed_table[line0].append((abs_lnnum, end_lnnum))
            self.collapsed_table[line0].sort(key=lambda item:item[0])
            self.regen_code(vu)

    def double_click(self, vu, shift_state):
        ccode = vu.cfunc.get_pseudocode()
        cur_lnnum = vu.cpos.lnnum
        self.log(cur_lnnum)
        sl = ccode.at(cur_lnnum)
        line_code = ida_lines.tag_remove(sl.line)
        if line_code.lstrip().startswith("{") or line_code.lstrip().startswith("case "):
            self.collapse(vu, ccode, line_code, cur_lnnum)

        return 0

    def close_pseudocode(self, vu):
        line0 = vu.cfunc.get_pseudocode().at(0).line[:]
        if line0 in self.collapsed_table:
            del self.collapsed_table[line0]
        if line0 in self.origin_code:
            del self.origin_code[line0]
        return 0

    def refresh_pseudocode(self, vu):
        line0 = vu.cfunc.get_pseudocode().at(0).line[:]
        if line0 in self.collapsed_table:
            del self.collapsed_table[line0]
        if line0 in self.origin_code:
            del self.origin_code[line0]
        return 0


class AphroditeF5Plugin(ida_idaapi.plugin_t):
    """
    """ 
    PLUGIN_NAME = "AphroditeF5"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "leommxj"

    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    comment = "Double click to collapse a code block in Hex-rays' decompiler"
    help = comment
    flags = ida_idaapi.PLUGIN_HIDE|ida_idaapi.PLUGIN_HIDE

    def __init__(self):
        self.hr_hook = None

    def init(self):
        print("AphroditeF5 is starting")
        if idaapi.init_hexrays_plugin():
            self.hr_hook = AphroditeHook()
            self.hr_hook.hook()
            return ida_idaapi.PLUGIN_KEEP
        else:
            return ida_idaapi.PLUGIN_SKIP

    @classmethod
    def description(cls):
        """Return the description displayed in the console."""
        return "{} v{}".format(cls.PLUGIN_NAME, cls.PLUGIN_VERSION)
    
    def run(self):
        return False
    
    def term(self):
        if self.hr_hook:
            self.hr_hook.unhook()
        idaapi.term_hexrays_plugin()
        

def PLUGIN_ENTRY():
    return AphroditeF5Plugin()
