# AfxMSGMap plugin for IDA
# Copyright (c) 2018
# Snow 85703533
# All rights reserved.
# 
# ==============================================================================



import idautils
import idaapi
import idc
import ida_segment
import ida_struct
import ida_nalt
import ida_typeinf

plugin_initialized = False



class AFXMSGMAPSearchResultChooser(idaapi.Choose2):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose2.__init__(
            self,
            title,
            [
                ["Index", idaapi.Choose2.CHCOL_PLAIN|6],
                ["Address", idaapi.Choose2.CHCOL_HEX|20],
                ["Name", idaapi.Choose2.CHCOL_HEX|40],
                ["Entry Num", idaapi.Choose2.CHCOL_HEX|10],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.Jump(self.items[n][1])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [str(res[0]), atoa(res[1]), res[2], str(res[3])]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0    
    
    
class AfxMSGMap:

    def __init__(self):
        self.cmin = 0
        self.cmax = 0
        self.rmin = 0
        self.rmax = 0
        self.msg_enum = 0
        self.MSGStructSize = 24
        self.USize = 4
        if (__EA64__):
            self.MSGStructSize = 32
            self.USize = 8

    def mt_rva(self):
        ri = refinfo_t()
        if (__EA64__):
            ri.flags = REF_OFF64
        else:
            ri.flags = REF_OFF32
        ri.target = BADADDR
        mt = opinfo_t()
        mt.ri = ri
        return mt
        
    def mt_ascii(self):
        ri = refinfo_t()
        ri.flags = ASCSTR_C
        ri.target = BADADDR
        mt = opinfo_t()
        mt.ri = ri
        return mt
        
    def AddMSGMAPStruct(self):
        name = "AFX_MSGMAP_ENTRY"
        idx = idaapi.get_struc_id(name)
        stru = idaapi.get_struc(idx)
        if (idx != BADADDR):
            #return idx
            idaapi.del_struc(stru)
        
        idx = idaapi.add_struc(BADADDR, name)
        stru = idaapi.get_struc(idx)
        
        if (idaapi.add_struc_member(stru, "nMessage", 0, FF_DATA|FF_DWRD, None, 4) != 0):
            Warning("Can't AddStrucMember nMessage\n")
            idaapi.del_struc(stru)
            return BADADDR
            
        if (idaapi.add_struc_member(stru, "nCode", 4, FF_DATA|FF_DWRD, None, 4) != 0):
            Warning("Can't AddStrucMember nCode\n")
            idaapi.del_struc(stru)
            return BADADDR
            
        if (idaapi.add_struc_member(stru, "nID", 8, FF_DATA|FF_DWRD, None, 4) != 0):
            Warning("Can't AddStrucMember nID\n")
            idaapi.del_struc(stru)
            return BADADDR
            
        if (idaapi.add_struc_member(stru, "nLastID", 12, FF_DATA|FF_DWRD, None, 4) != 0):
            Warning("Can't AddStrucMember nLastID\n")
            idaapi.del_struc(stru)
            return BADADDR
            
        if (__EA64__):
            if (idaapi.add_struc_member(stru, "nSig", 16, FF_DATA|FF_QWRD, None, 8) != 0):
                Warning("Can't AddStrucMember nSig\n")
                idaapi.del_struc(stru)
                return BADADDR
                
            if (idaapi.add_struc_member(stru, "pfn", 24, FF_DATA|FF_DWRD|FF_0OFF, self.mt_rva(), 8) != 0):
                Warning("Can't AddStrucMember pfn\n")
                idaapi.del_struc(stru)
                return BADADDR
        else:
            if (idaapi.add_struc_member(stru, "nSig", 16, FF_DATA|FF_DWRD, None, 4) != 0):
                Warning("Can't AddStrucMember nSig\n")
                idaapi.del_struc(stru)
                return BADADDR
                
            if (idaapi.add_struc_member(stru, "pfn", 20, FF_DATA|FF_DWRD|FF_0OFF, self.mt_rva(), 4) != 0):
                Warning("Can't AddStrucMember pfn\n")
                idaapi.del_struc(stru)
                return BADADDR
        
    def GetMsgName(self, msgid):
        if (msgid == 0x0000):return "WM_NULL"
        if (msgid == 0x0001):return "WM_CREATE"
        if (msgid == 0x0002):return "WM_DESTROY"
        if (msgid == 0x0003):return "WM_MOVE"
        if (msgid == 0x0004):return "WM_SIZEWAIT"
        if (msgid == 0x0005):return "WM_SIZE"
        if (msgid == 0x0006):return "WM_ACTIVATE"
        if (msgid == 0x0007):return "WM_SETFOCUS"
        if (msgid == 0x0008):return "WM_KILLFOCUS"
        if (msgid == 0x0009):return "WM_SETVISIBLE"
        if (msgid == 0x000a):return "WM_ENABLE"
        if (msgid == 0x000b):return "WM_SETREDRAW"
        if (msgid == 0x000c):return "WM_SETTEXT"
        if (msgid == 0x000d):return "WM_GETTEXT"
        if (msgid == 0x000e):return "WM_GETTEXTLENGTH"
        if (msgid == 0x000f):return "WM_PAINT"
        if (msgid == 0x0010):return "WM_CLOSE"
        if (msgid == 0x0011):return "WM_QUERYENDSESSION"
        if (msgid == 0x0012):return "WM_QUIT"
        if (msgid == 0x0013):return "WM_QUERYOPEN"
        if (msgid == 0x0014):return "WM_ERASEBKGND"
        if (msgid == 0x0015):return "WM_SYSCOLORCHANGE"
        if (msgid == 0x0016):return "WM_ENDSESSION"
        if (msgid == 0x0017):return "WM_SYSTEMERROR"
        if (msgid == 0x0018):return "WM_SHOWWINDOW"
        if (msgid == 0x0019):return "WM_CTLCOLOR"
        if (msgid == 0x001a):return "WM_WININICHANGE"
        if (msgid == 0x001b):return "WM_DEVMODECHANGE"
        if (msgid == 0x001c):return "WM_ACTIVATEAPP"
        if (msgid == 0x001d):return "WM_FONTCHANGE"
        if (msgid == 0x001e):return "WM_TIMECHANGE"
        if (msgid == 0x001f):return "WM_CANCELMODE"
        if (msgid == 0x0020):return "WM_SETCURSOR"
        if (msgid == 0x0021):return "WM_MOUSEACTIVATE"
        if (msgid == 0x0022):return "WM_CHILDACTIVATE"
        if (msgid == 0x0023):return "WM_QUEUESYNC"
        if (msgid == 0x0024):return "WM_GETMINMAXINFO"
        if (msgid == 0x0025):return "WM_LOGOFF"
        if (msgid == 0x0026):return "WM_PAINTICON"
        if (msgid == 0x0027):return "WM_ICONERASEBKGND"
        if (msgid == 0x0028):return "WM_NEXTDLGCTL"
        if (msgid == 0x0029):return "WM_ALTTABACTIVE"
        if (msgid == 0x002a):return "WM_SPOOLERSTATUS"
        if (msgid == 0x002b):return "WM_DRAWITEM"
        if (msgid == 0x002c):return "WM_MEASUREITEM"
        if (msgid == 0x002d):return "WM_DELETEITEM"
        if (msgid == 0x002e):return "WM_VKEYTOITEM"
        if (msgid == 0x002f):return "WM_CHARTOITEM"
        if (msgid == 0x0030):return "WM_SETFONT"
        if (msgid == 0x0031):return "WM_GETFONT"
        if (msgid == 0x0032):return "WM_SETHOTKEY"
        if (msgid == 0x0033):return "WM_GETHOTKEY"
        if (msgid == 0x0034):return "WM_FILESYSCHANGE"
        if (msgid == 0x0035):return "WM_ISACTIVEICON"
        if (msgid == 0x0036):return "WM_QUERYPARKICON"
        if (msgid == 0x0037):return "WM_QUERYDRAGICON"
        if (msgid == 0x0038):return "WM_WINHELP"
        if (msgid == 0x0039):return "WM_COMPAREITEM"
        if (msgid == 0x003a):return "WM_FULLSCREEN"
        if (msgid == 0x003b):return "WM_CLIENTSHUTDOWN"
        if (msgid == 0x003c):return "WM_DDEMLEVENT"
        if (msgid == 0x003d):return "WM_GETOBJECT"
        if (msgid == 0x003e):return "WM_UNDEF_0x003e"
        if (msgid == 0x003f):return "WM_CALCSCROLL"
        if (msgid == 0x0040):return "WM_TESTING"
        if (msgid == 0x0041):return "WM_COMPACTING"
        if (msgid == 0x0042):return "WM_OTHERWINDOWCREATED"
        if (msgid == 0x0043):return "WM_OTHERWINDOWDESTROYED"
        if (msgid == 0x0044):return "WM_COMMNOTIFY"
        if (msgid == 0x0045):return "WM_MEDIASTATUSCHANGE"
        if (msgid == 0x0046):return "WM_WINDOWPOSCHANGING"
        if (msgid == 0x0047):return "WM_WINDOWPOSCHANGED"
        if (msgid == 0x0048):return "WM_POWER"
        if (msgid == 0x0049):return "WM_COPYGLOBALDATA"
        if (msgid == 0x004a):return "WM_COPYDATA"
        if (msgid == 0x004b):return "WM_CANCELJOURNAL"
        if (msgid == 0x004c):return "WM_LOGONNOTIFY"
        if (msgid == 0x004d):return "WM_KEYF1"
        if (msgid == 0x004e):return "WM_NOTIFY"
        if (msgid == 0x004f):return "WM_ACCESS_WINDOW"
        if (msgid == 0x0050):return "WM_INPUTLANGCHANGEREQUEST"
        if (msgid == 0x0051):return "WM_INPUTLANGCHANGE"
        if (msgid == 0x0052):return "WM_TCARD"
        if (msgid == 0x0053):return "WM_HELP"
        if (msgid == 0x0054):return "WM_USERCHANGED"
        if (msgid == 0x0055):return "WM_NOTIFYFORMAT"
        if (msgid == 0x0056):return "WM_UNDEF_0x0056"
        if (msgid == 0x0057):return "WM_UNDEF_0x0057"
        if (msgid == 0x0058):return "WM_UNDEF_0x0058"
        if (msgid == 0x0059):return "WM_UNDEF_0x0059"
        if (msgid == 0x005a):return "WM_UNDEF_0x005a"
        if (msgid == 0x005b):return "WM_UNDEF_0x005b"
        if (msgid == 0x005c):return "WM_UNDEF_0x005c"
        if (msgid == 0x005d):return "WM_UNDEF_0x005d"
        if (msgid == 0x005e):return "WM_UNDEF_0x005e"
        if (msgid == 0x005f):return "WM_UNDEF_0x005f"
        if (msgid == 0x0060):return "WM_UNDEF_0x0060"
        if (msgid == 0x0061):return "WM_UNDEF_0x0061"
        if (msgid == 0x0062):return "WM_UNDEF_0x0062"
        if (msgid == 0x0063):return "WM_UNDEF_0x0063"
        if (msgid == 0x0064):return "WM_UNDEF_0x0064"
        if (msgid == 0x0065):return "WM_UNDEF_0x0065"
        if (msgid == 0x0066):return "WM_UNDEF_0x0066"
        if (msgid == 0x0067):return "WM_UNDEF_0x0067"
        if (msgid == 0x0068):return "WM_UNDEF_0x0068"
        if (msgid == 0x0069):return "WM_UNDEF_0x0069"
        if (msgid == 0x006a):return "WM_UNDEF_0x006a"
        if (msgid == 0x006b):return "WM_UNDEF_0x006b"
        if (msgid == 0x006c):return "WM_UNDEF_0x006c"
        if (msgid == 0x006d):return "WM_UNDEF_0x006d"
        if (msgid == 0x006e):return "WM_UNDEF_0x006e"
        if (msgid == 0x006f):return "WM_UNDEF_0x006f"
        if (msgid == 0x0070):return "WM_FINALDESTROY"
        if (msgid == 0x0071):return "WM_MEASUREITEM_CLIENTDATA"
        if (msgid == 0x0072):return "WM_TASKACTIVATED"
        if (msgid == 0x0073):return "WM_TASKDEACTIVATED"
        if (msgid == 0x0074):return "WM_TASKCREATED"
        if (msgid == 0x0075):return "WM_TASKDESTROYED"
        if (msgid == 0x0076):return "WM_TASKUICHANGED"
        if (msgid == 0x0077):return "WM_TASKVISIBLE"
        if (msgid == 0x0078):return "WM_TASKNOTVISIBLE"
        if (msgid == 0x0079):return "WM_SETCURSORINFO"
        if (msgid == 0x007a):return "WM_UNDEF_0x007a"
        if (msgid == 0x007b):return "WM_CONTEXTMENU"
        if (msgid == 0x007c):return "WM_STYLECHANGING"
        if (msgid == 0x007d):return "WM_STYLECHANGED"
        if (msgid == 0x007e):return "WM_DISPLAYCHANGE"
        if (msgid == 0x007f):return "WM_GETICON"
        if (msgid == 0x0080):return "WM_SETICON"
        if (msgid == 0x0081):return "WM_NCCREATE"
        if (msgid == 0x0082):return "WM_NCDESTROY"
        if (msgid == 0x0083):return "WM_NCCALCSIZE"
        if (msgid == 0x0084):return "WM_NCHITTEST"
        if (msgid == 0x0085):return "WM_NCPAINT"
        if (msgid == 0x0086):return "WM_NCACTIVATE"
        if (msgid == 0x0087):return "WM_GETDLGCODE"
        if (msgid == 0x0088):return "WM_SYNCPAINT"
        if (msgid == 0x0089):return "WM_SYNCTASK"
        if (msgid == 0x008a):return "WM_UNDEF_0x008a"
        if (msgid == 0x008b):return "WM_KLUDGEMINRECT"
        if (msgid == 0x008c):return "WM_LPKDRAWSWITCHWND"
        if (msgid == 0x008d):return "WM_UNDEF_0x008d"
        if (msgid == 0x008e):return "WM_UNDEF_0x008e"
        if (msgid == 0x008f):return "WM_UNDEF_0x008f"
        if (msgid == 0x0090):return "WM_UNDEF_0x0090"
        if (msgid == 0x0091):return "WM_UNDEF_0x0091"
        if (msgid == 0x0092):return "WM_UNDEF_0x0092"
        if (msgid == 0x0093):return "WM_UNDEF_0x0093"
        if (msgid == 0x0094):return "WM_UNDEF_0x0094"
        if (msgid == 0x0095):return "WM_UNDEF_0x0095"
        if (msgid == 0x0096):return "WM_UNDEF_0x0096"
        if (msgid == 0x0097):return "WM_UNDEF_0x0097"
        if (msgid == 0x0098):return "WM_UNDEF_0x0098"
        if (msgid == 0x0099):return "WM_UNDEF_0x0099"
        if (msgid == 0x009a):return "WM_UNDEF_0x009a"
        if (msgid == 0x009b):return "WM_UNDEF_0x009b"
        if (msgid == 0x009c):return "WM_UNDEF_0x009c"
        if (msgid == 0x009d):return "WM_UNDEF_0x009d"
        if (msgid == 0x009e):return "WM_UNDEF_0x009e"
        if (msgid == 0x009f):return "WM_UNDEF_0x009f"
        if (msgid == 0x00A0):return "WM_NCMOUSEMOVE"
        if (msgid == 0x00A1):return "WM_NCLBUTTONDOWN"
        if (msgid == 0x00A2):return "WM_NCLBUTTONUP"
        if (msgid == 0x00A3):return "WM_NCLBUTTONDBLCLK"
        if (msgid == 0x00A4):return "WM_NCRBUTTONDOWN"
        if (msgid == 0x00A5):return "WM_NCRBUTTONUP"
        if (msgid == 0x00A6):return "WM_NCRBUTTONDBLCLK"
        if (msgid == 0x00A7):return "WM_NCMBUTTONDOWN"
        if (msgid == 0x00A8):return "WM_NCMBUTTONUP"
        if (msgid == 0x00A9):return "WM_NCMBUTTONDBLCLK"
        if (msgid == 0x00AA):return "WM_UNDEF_0x00AA"
        if (msgid == 0x00AB):return "WM_NCXBUTTONDOWN"
        if (msgid == 0x00AC):return "WM_NCXBUTTONUP"
        if (msgid == 0x00AD):return "WM_NCXBUTTONDBLCLK"
        if (msgid == 0x00AE):return "WM_NCUAHDRAWCAPTION"
        if (msgid == 0x00AF):return "WM_NCUAHDRAWFRAME"
        if (msgid == 0x00b0):return "EM_GETSEL32"
        if (msgid == 0x00b1):return "EM_SETSEL32"
        if (msgid == 0x00b2):return "EM_GETRECT32"
        if (msgid == 0x00b3):return "EM_SETRECT32"
        if (msgid == 0x00b4):return "EM_SETRECTNP32"
        if (msgid == 0x00b5):return "EM_SCROLL32"
        if (msgid == 0x00b6):return "EM_LINESCROLL32"
        if (msgid == 0x00b7):return "EM_SCROLLCARET32"
        if (msgid == 0x00b8):return "EM_GETMODIFY32"
        if (msgid == 0x00b9):return "EM_SETMODIFY32"
        if (msgid == 0x00ba):return "EM_GETLINECOUNT32"
        if (msgid == 0x00bb):return "EM_LINEINDEX32"
        if (msgid == 0x00bc):return "EM_SETHANDLE32"
        if (msgid == 0x00bd):return "EM_GETHANDLE32"
        if (msgid == 0x00be):return "EM_GETTHUMB32"
        if (msgid == 0x00bf):return "WM_UNDEF_0x00bf"
        if (msgid == 0x00c0):return "WM_UNDEF_0x00c0"
        if (msgid == 0x00c1):return "EM_LINELENGTH32"
        if (msgid == 0x00c2):return "EM_REPLACESEL32"
        if (msgid == 0x00c3):return "EM_SETFONT"
        if (msgid == 0x00c4):return "EM_GETLINE32"
        if (msgid == 0x00c5):return "EM_LIMITTEXT32"
        if (msgid == 0x00c6):return "EM_CANUNDO32"
        if (msgid == 0x00c7):return "EM_UNDO32"
        if (msgid == 0x00c8):return "EM_FMTLINES32"
        if (msgid == 0x00c9):return "EM_LINEFROMCHAR32"
        if (msgid == 0x00ca):return "EM_SETWORDBREAK"
        if (msgid == 0x00cb):return "EM_SETTABSTOPS32"
        if (msgid == 0x00cc):return "EM_SETPASSWORDCHAR32"
        if (msgid == 0x00cd):return "EM_EMPTYUNDOBUFFER32"
        if (msgid == 0x00ce):return "EM_GETFIRSTVISIBLELINE32"
        if (msgid == 0x00cf):return "EM_SETREADONLY32"
        if (msgid == 0x00d0):return "EM_SETWORDBREAKPROC32"
        if (msgid == 0x00d1):return "EM_GETWORDBREAKPROC32"
        if (msgid == 0x00d2):return "EM_GETPASSWORDCHAR32"
        if (msgid == 0x00d3):return "EM_SETMARGINS32"
        if (msgid == 0x00d4):return "EM_GETMARGINS32"
        if (msgid == 0x00d5):return "EM_GETLIMITTEXT32"
        if (msgid == 0x00d6):return "EM_POSFROMCHAR32"
        if (msgid == 0x00d7):return "EM_CHARFROMPOS32"
        if (msgid == 0x00D8):return "EM_SETIMESTATUS"
        if (msgid == 0x00D9):return "EM_GETIMESTATUS"
        if (msgid == 0x00DA):return "EM_MSGMAX"
        if (msgid == 0x00DB):return "WM_UNDEF_0x00DB"
        if (msgid == 0x00DC):return "WM_UNDEF_0x00DC"
        if (msgid == 0x00DD):return "WM_UNDEF_0x00DD"
        if (msgid == 0x00DE):return "WM_UNDEF_0x00DE"
        if (msgid == 0x00DF):return "WM_UNDEF_0x00DF"
        if (msgid == 0x00e0):return "SBM_SETPOS32"
        if (msgid == 0x00e1):return "SBM_GETPOS32"
        if (msgid == 0x00e2):return "SBM_SETRANGE32"
        if (msgid == 0x00e3):return "SBM_GETRANGE32"
        if (msgid == 0x00e4):return "SBM_ENABLE_ARROWS32"
        if (msgid == 0x00e5):return "WM_UNDEF_0x00e5"
        if (msgid == 0x00e6):return "SBM_SETRANGEREDRAW32"
        if (msgid == 0x00e7):return "WM_UNDEF_0x00e7"
        if (msgid == 0x00e8):return "WM_UNDEF_0x00e8"
        if (msgid == 0x00e9):return "SBM_SETSCROLLINFO32"
        if (msgid == 0x00ea):return "SBM_GETSCROLLINFO32"
        if (msgid == 0x00eb):return "WM_UNDEF_0x00eb"
        if (msgid == 0x00ec):return "WM_UNDEF_0x00ec"
        if (msgid == 0x00ed):return "WM_UNDEF_0x00ed"
        if (msgid == 0x00ee):return "WM_UNDEF_0x00ee"
        if (msgid == 0x00ef):return "WM_UNDEF_0x00ef"
        if (msgid == 0x00f0):return "BM_GETCHECK32"
        if (msgid == 0x00f1):return "BM_SETCHECK32"
        if (msgid == 0x00f2):return "BM_GETSTATE32"
        if (msgid == 0x00f3):return "BM_SETSTATE32"
        if (msgid == 0x00f4):return "BM_SETSTYLE32"
        if (msgid == 0x00f5):return "BM_CLICK32"
        if (msgid == 0x00f6):return "BM_GETIMAGE32"
        if (msgid == 0x00f7):return "BM_SETIMAGE32"
        if (msgid == 0x00f8):return "WM_UNDEF_0x00f8"
        if (msgid == 0x00f9):return "WM_UNDEF_0x00f9"
        if (msgid == 0x00fa):return "WM_UNDEF_0x00fa"
        if (msgid == 0x00fb):return "WM_UNDEF_0x00fb"
        if (msgid == 0x00fc):return "WM_UNDEF_0x00fc"
        if (msgid == 0x00fd):return "WM_UNDEF_0x00fd"
        if (msgid == 0x00fe):return "WM_UNDEF_0x00fe"
        if (msgid == 0x00ff):return "WM_INPUT"
        if (msgid == 0x0100):return "WM_KEYDOWN"
        if (msgid == 0x0101):return "WM_KEYUP"
        if (msgid == 0x0102):return "WM_CHAR"
        if (msgid == 0x0103):return "WM_DEADCHAR"
        if (msgid == 0x0104):return "WM_SYSKEYDOWN"
        if (msgid == 0x0105):return "WM_SYSKEYUP"
        if (msgid == 0x0106):return "WM_SYSCHAR"
        if (msgid == 0x0107):return "WM_SYSDEADCHAR"
        if (msgid == 0x0108):return "WM_YOMICHAR"
        if (msgid == 0x0109):return "WM_UNICHAR"
        if (msgid == 0x010a):return "WM_CONVERTREQUEST"
        if (msgid == 0x010b):return "WM_CONVERTRESULT"
        if (msgid == 0x010c):return "WM_INTERIM"
        if (msgid == 0x010d):return "WM_IME_STARTCOMPOSITION"
        if (msgid == 0x010e):return "WM_IME_ENDCOMPOSITION"
        if (msgid == 0x010f):return "WM_IME_COMPOSITION"
        if (msgid == 0x0110):return "WM_INITDIALOG"
        if (msgid == 0x0111):return "WM_COMMAND"
        if (msgid == 0x0112):return "WM_SYSCOMMAND"
        if (msgid == 0x0113):return "WM_TIMER"
        if (msgid == 0x0114):return "WM_HSCROLL"
        if (msgid == 0x0115):return "WM_VSCROLL"
        if (msgid == 0x0116):return "WM_INITMENU"
        if (msgid == 0x0117):return "WM_INITMENUPOPUP"
        if (msgid == 0x0118):return "WM_SYSTIMER"
        if (msgid == 0x0119):return "WM_UNDEF_0x0119"
        if (msgid == 0x011a):return "WM_UNDEF_0x011a"
        if (msgid == 0x011b):return "WM_UNDEF_0x011b"
        if (msgid == 0x011c):return "WM_UNDEF_0x011c"
        if (msgid == 0x011d):return "WM_UNDEF_0x011d"
        if (msgid == 0x011e):return "WM_UNDEF_0x011e"
        if (msgid == 0x011f):return "WM_MENUSELECT"
        if (msgid == 0x0120):return "WM_MENUCHAR"
        if (msgid == 0x0121):return "WM_ENTERIDLE"
        if (msgid == 0x0122):return "WM_MENURBUTTONUP"
        if (msgid == 0x0123):return "WM_MENUDRAG"
        if (msgid == 0x0124):return "WM_MENUGETOBJECT"
        if (msgid == 0x0125):return "WM_UNINITMENUPOPUP"
        if (msgid == 0x0126):return "WM_MENUCOMMAND"
        if (msgid == 0x0127):return "WM_CHANGEUISTATE"
        if (msgid == 0x0128):return "WM_UPDATEUISTATE"
        if (msgid == 0x0129):return "WM_QUERYUISTATE"
        if (msgid == 0x012a):return "WM_UNDEF_0x012a"
        if (msgid == 0x012b):return "WM_UNDEF_0x012b"
        if (msgid == 0x012c):return "WM_UNDEF_0x012c"
        if (msgid == 0x012d):return "WM_UNDEF_0x012d"
        if (msgid == 0x012e):return "WM_UNDEF_0x012e"
        if (msgid == 0x012f):return "WM_UNDEF_0x012f"
        if (msgid == 0x0130):return "WM_UNDEF_0x0130"
        if (msgid == 0x0131):return "WM_LBTRACKPOINT"
        if (msgid == 0x0132):return "WM_CTLCOLORMSGBOX"
        if (msgid == 0x0133):return "WM_CTLCOLOREDIT"
        if (msgid == 0x0134):return "WM_CTLCOLORLISTBOX"
        if (msgid == 0x0135):return "WM_CTLCOLORBTN"
        if (msgid == 0x0136):return "WM_CTLCOLORDLG"
        if (msgid == 0x0137):return "WM_CTLCOLORSCROLLBAR"
        if (msgid == 0x0138):return "WM_CTLCOLORSTATIC"
        if (msgid == 0x0139):return "WM_UNDEF_0x0139"
        if (msgid == 0x013a):return "WM_UNDEF_0x013a"
        if (msgid == 0x013b):return "WM_UNDEF_0x013b"
        if (msgid == 0x013c):return "WM_UNDEF_0x013c"
        if (msgid == 0x013d):return "WM_UNDEF_0x013d"
        if (msgid == 0x013e):return "WM_UNDEF_0x013e"
        if (msgid == 0x013f):return "WM_UNDEF_0x013f"
        if (msgid == 0x0140):return "CB_GETEDITSEL32"
        if (msgid == 0x0141):return "CB_LIMITTEXT32"
        if (msgid == 0x0142):return "CB_SETEDITSEL32"
        if (msgid == 0x0143):return "CB_ADDSTRING32"
        if (msgid == 0x0144):return "CB_DELETESTRING32"
        if (msgid == 0x0145):return "CB_DIR32"
        if (msgid == 0x0146):return "CB_GETCOUNT32"
        if (msgid == 0x0147):return "CB_GETCURSEL32"
        if (msgid == 0x0148):return "CB_GETLBTEXT32"
        if (msgid == 0x0149):return "CB_GETLBTEXTLEN32"
        if (msgid == 0x014a):return "CB_INSERTSTRING32"
        if (msgid == 0x014b):return "CB_RESETCONTENT32"
        if (msgid == 0x014c):return "CB_FINDSTRING32"
        if (msgid == 0x014d):return "CB_SELECTSTRING32"
        if (msgid == 0x014e):return "CB_SETCURSEL32"
        if (msgid == 0x014f):return "CB_SHOWDROPDOWN32"
        if (msgid == 0x0150):return "CB_GETITEMDATA32"
        if (msgid == 0x0151):return "CB_SETITEMDATA32"
        if (msgid == 0x0152):return "CB_GETDROPPEDCONTROLRECT32"
        if (msgid == 0x0153):return "CB_SETITEMHEIGHT32"
        if (msgid == 0x0154):return "CB_GETITEMHEIGHT32"
        if (msgid == 0x0155):return "CB_SETEXTENDEDUI32"
        if (msgid == 0x0156):return "CB_GETEXTENDEDUI32"
        if (msgid == 0x0157):return "CB_GETDROPPEDSTATE32"
        if (msgid == 0x0158):return "CB_FINDSTRINGEXACT32"
        if (msgid == 0x0159):return "CB_SETLOCALE32"
        if (msgid == 0x015a):return "CB_GETLOCALE32"
        if (msgid == 0x015b):return "CB_GETTOPINDEX32"
        if (msgid == 0x015c):return "CB_SETTOPINDEX32"
        if (msgid == 0x015d):return "CB_GETHORIZONTALEXTENT32"
        if (msgid == 0x015e):return "CB_SETHORIZONTALEXTENT32"
        if (msgid == 0x015f):return "CB_GETDROPPEDWIDTH32"
        if (msgid == 0x0160):return "CB_SETDROPPEDWIDTH32"
        if (msgid == 0x0161):return "CB_INITSTORAGE32"
        if (msgid == 0x0162):return "WM_UNDEF_0x0162"
        if (msgid == 0x0163):return "CB_MULTIPLEADDSTRING"
        if (msgid == 0x0164):return "CB_GETCOMBOBOXINFO"
        if (msgid == 0x0165):return "WM_UNDEF_0x0165"
        if (msgid == 0x0166):return "WM_UNDEF_0x0166"
        if (msgid == 0x0167):return "WM_UNDEF_0x0167"
        if (msgid == 0x0168):return "WM_UNDEF_0x0168"
        if (msgid == 0x0169):return "WM_UNDEF_0x0169"
        if (msgid == 0x016a):return "WM_UNDEF_0x016a"
        if (msgid == 0x016b):return "WM_UNDEF_0x016b"
        if (msgid == 0x016c):return "WM_UNDEF_0x016c"
        if (msgid == 0x016d):return "WM_UNDEF_0x016d"
        if (msgid == 0x016e):return "WM_UNDEF_0x016e"
        if (msgid == 0x016f):return "WM_UNDEF_0x016f"
        if (msgid == 0x0170):return "STM_SETICON32"
        if (msgid == 0x0171):return "STM_GETICON32"
        if (msgid == 0x0172):return "STM_SETIMAGE32"
        if (msgid == 0x0173):return "STM_GETIMAGE32"
        if (msgid == 0x0174):return "STM_MSGMAX"
        if (msgid == 0x0175):return "WM_UNDEF_0x0175"
        if (msgid == 0x0176):return "WM_UNDEF_0x0176"
        if (msgid == 0x0177):return "WM_UNDEF_0x0177"
        if (msgid == 0x0178):return "WM_UNDEF_0x0178"
        if (msgid == 0x0179):return "WM_UNDEF_0x0179"
        if (msgid == 0x017a):return "WM_UNDEF_0x017a"
        if (msgid == 0x017b):return "WM_UNDEF_0x017b"
        if (msgid == 0x017c):return "WM_UNDEF_0x017c"
        if (msgid == 0x017d):return "WM_UNDEF_0x017d"
        if (msgid == 0x017e):return "WM_UNDEF_0x017e"
        if (msgid == 0x017f):return "WM_UNDEF_0x017f"
        if (msgid == 0x0180):return "LB_ADDSTRING32"
        if (msgid == 0x0181):return "LB_INSERTSTRING32"
        if (msgid == 0x0182):return "LB_DELETESTRING32"
        if (msgid == 0x0183):return "LB_SELITEMRANGEEX32"
        if (msgid == 0x0184):return "LB_RESETCONTENT32"
        if (msgid == 0x0185):return "LB_SETSEL32"
        if (msgid == 0x0186):return "LB_SETCURSEL32"
        if (msgid == 0x0187):return "LB_GETSEL32"
        if (msgid == 0x0188):return "LB_GETCURSEL32"
        if (msgid == 0x0189):return "LB_GETTEXT32"
        if (msgid == 0x018a):return "LB_GETTEXTLEN32"
        if (msgid == 0x018b):return "LB_GETCOUNT32"
        if (msgid == 0x018c):return "LB_SELECTSTRING32"
        if (msgid == 0x018d):return "LB_DIR32"
        if (msgid == 0x018e):return "LB_GETTOPINDEX32"
        if (msgid == 0x018f):return "LB_FINDSTRING32"
        if (msgid == 0x0190):return "LB_GETSELCOUNT32"
        if (msgid == 0x0191):return "LB_GETSELITEMS32"
        if (msgid == 0x0192):return "LB_SETTABSTOPS32"
        if (msgid == 0x0193):return "LB_GETHORIZONTALEXTENT32"
        if (msgid == 0x0194):return "LB_SETHORIZONTALEXTENT32"
        if (msgid == 0x0195):return "LB_SETCOLUMNWIDTH32"
        if (msgid == 0x0196):return "LB_ADDFILE32"
        if (msgid == 0x0197):return "LB_SETTOPINDEX32"
        if (msgid == 0x0198):return "LB_GETITEMRECT32"
        if (msgid == 0x0199):return "LB_GETITEMDATA32"
        if (msgid == 0x019a):return "LB_SETITEMDATA32"
        if (msgid == 0x019b):return "LB_SELITEMRANGE32"
        if (msgid == 0x019c):return "LB_SETANCHORINDEX32"
        if (msgid == 0x019d):return "LB_GETANCHORINDEX32"
        if (msgid == 0x019e):return "LB_SETCARETINDEX32"
        if (msgid == 0x019f):return "LB_GETCARETINDEX32"
        if (msgid == 0x01a0):return "LB_SETITEMHEIGHT32"
        if (msgid == 0x01a1):return "LB_GETITEMHEIGHT32"
        if (msgid == 0x01a2):return "LB_FINDSTRINGEXACT32"
        if (msgid == 0x01a3):return "LB_CARETON32"
        if (msgid == 0x01a4):return "LB_CARETOFF32"
        if (msgid == 0x01a5):return "LB_SETLOCALE32"
        if (msgid == 0x01a6):return "LB_GETLOCALE32"
        if (msgid == 0x01a7):return "LB_SETCOUNT32"
        if (msgid == 0x01a8):return "LB_INITSTORAGE32"
        if (msgid == 0x01a9):return "LB_ITEMFROMPOINT32"
        if (msgid == 0x01aa):return "LB_INSERTSTRINGUPPER"
        if (msgid == 0x01ab):return "LB_INSERTSTRINGLOWER"
        if (msgid == 0x01ac):return "LB_ADDSTRINGUPPER"
        if (msgid == 0x01ad):return "LB_ADDSTRINGLOWER"
        if (msgid == 0x01ae):return "LBCB_STARTTRACK"
        if (msgid == 0x01af):return "LBCB_ENDTRACK"
        if (msgid == 0x01B0):return "WM_UNDEF_0x01B0"
        if (msgid == 0x01b1):return "LB_MULTIPLEADDSTRING"
        if (msgid == 0x01b2):return "LB_GETLISTBOXINFO"
        if (msgid == 0x01b3):return "WM_UNDEF_0x01b3"
        if (msgid == 0x01b4):return "WM_UNDEF_0x01b4"
        if (msgid == 0x01b5):return "WM_UNDEF_0x01b5"
        if (msgid == 0x01b6):return "WM_UNDEF_0x01b6"
        if (msgid == 0x01b7):return "WM_UNDEF_0x01b7"
        if (msgid == 0x01b8):return "WM_UNDEF_0x01b8"
        if (msgid == 0x01b9):return "WM_UNDEF_0x01b9"
        if (msgid == 0x01ba):return "WM_UNDEF_0x01ba"
        if (msgid == 0x01bb):return "WM_UNDEF_0x01bb"
        if (msgid == 0x01bc):return "WM_UNDEF_0x01bc"
        if (msgid == 0x01bd):return "WM_UNDEF_0x01bd"
        if (msgid == 0x01be):return "WM_UNDEF_0x01be"
        if (msgid == 0x01bf):return "WM_UNDEF_0x01bf"
        if (msgid == 0x01C0):return "WM_UNDEF_0x01C0"
        if (msgid == 0x01c1):return "WM_UNDEF_0x01c1"
        if (msgid == 0x01c2):return "WM_UNDEF_0x01c2"
        if (msgid == 0x01c3):return "WM_UNDEF_0x01c3"
        if (msgid == 0x01c4):return "WM_UNDEF_0x01c4"
        if (msgid == 0x01c5):return "WM_UNDEF_0x01c5"
        if (msgid == 0x01c6):return "WM_UNDEF_0x01c6"
        if (msgid == 0x01c7):return "WM_UNDEF_0x01c7"
        if (msgid == 0x01c8):return "WM_UNDEF_0x01c8"
        if (msgid == 0x01c9):return "WM_UNDEF_0x01c9"
        if (msgid == 0x01ca):return "WM_UNDEF_0x01ca"
        if (msgid == 0x01cb):return "WM_UNDEF_0x01cb"
        if (msgid == 0x01cc):return "WM_UNDEF_0x01cc"
        if (msgid == 0x01cd):return "WM_UNDEF_0x01cd"
        if (msgid == 0x01ce):return "WM_UNDEF_0x01ce"
        if (msgid == 0x01cf):return "WM_UNDEF_0x01cf"
        if (msgid == 0x01D0):return "WM_UNDEF_0x01D0"
        if (msgid == 0x01d1):return "WM_UNDEF_0x01d1"
        if (msgid == 0x01d2):return "WM_UNDEF_0x01d2"
        if (msgid == 0x01d3):return "WM_UNDEF_0x01d3"
        if (msgid == 0x01d4):return "WM_UNDEF_0x01d4"
        if (msgid == 0x01d5):return "WM_UNDEF_0x01d5"
        if (msgid == 0x01d6):return "WM_UNDEF_0x01d6"
        if (msgid == 0x01d7):return "WM_UNDEF_0x01d7"
        if (msgid == 0x01d8):return "WM_UNDEF_0x01d8"
        if (msgid == 0x01d9):return "WM_UNDEF_0x01d9"
        if (msgid == 0x01da):return "WM_UNDEF_0x01da"
        if (msgid == 0x01db):return "WM_UNDEF_0x01db"
        if (msgid == 0x01dc):return "WM_UNDEF_0x01dc"
        if (msgid == 0x01dd):return "WM_UNDEF_0x01dd"
        if (msgid == 0x01de):return "WM_UNDEF_0x01de"
        if (msgid == 0x01df):return "WM_UNDEF_0x01df"
        if (msgid == 0x01E0):return "WM_UNDEF_0x01E0"
        if (msgid == 0x01e1):return "WM_UNDEF_0x01e1"
        if (msgid == 0x01e2):return "WM_UNDEF_0x01e2"
        if (msgid == 0x01e3):return "MN_SETHMENU"
        if (msgid == 0x01e4):return "MN_GETHMENU"
        if (msgid == 0x01e5):return "MN_SIZEWINDOW"
        if (msgid == 0x01e6):return "MN_OPENHIERARCHY"
        if (msgid == 0x01e7):return "MN_CLOSEHIERARCHY"
        if (msgid == 0x01e8):return "MN_SELECTITEM"
        if (msgid == 0x01e9):return "MN_CANCELMENUS"
        if (msgid == 0x01ea):return "MN_SELECTFIRSTVALIDITEM"
        if (msgid == 0x01eb):return "WM_UNDEF_0x01eb"
        if (msgid == 0x01ec):return "WM_UNDEF_0x01ec"
        if (msgid == 0x01ed):return "WM_UNDEF_0x01ed"
        if (msgid == 0x01ee):return "MN_FINDMENUWINDOWFROMPOINT"
        if (msgid == 0x01ef):return "MN_SHOWPOPUPWINDOW"
        if (msgid == 0x01f0):return "MN_BUTTONUP"
        if (msgid == 0x01f1):return "MN_SETTIMERTOOPENHIERARCHY"
        if (msgid == 0x01f2):return "MN_DBLCLK"
        if (msgid == 0x01f3):return "MN_ACTIVEPOPUP"
        if (msgid == 0x01f4):return "MN_ENDMENU"
        if (msgid == 0x01f5):return "MN_DODRAGDROP"
        if (msgid == 0x01f6):return "WM_UNDEF_0x01f6"
        if (msgid == 0x01f7):return "WM_UNDEF_0x01f7"
        if (msgid == 0x01f8):return "WM_UNDEF_0x01f8"
        if (msgid == 0x01f9):return "WM_UNDEF_0x01f9"
        if (msgid == 0x01fa):return "WM_UNDEF_0x01fa"
        if (msgid == 0x01fb):return "WM_UNDEF_0x01fb"
        if (msgid == 0x01fc):return "WM_UNDEF_0x01fc"
        if (msgid == 0x01fd):return "WM_UNDEF_0x01fd"
        if (msgid == 0x01fe):return "WM_UNDEF_0x01fe"
        if (msgid == 0x01ff):return "WM_UNDEF_0x01ff"
        if (msgid == 0x0200):return "WM_MOUSEMOVE"
        if (msgid == 0x0201):return "WM_LBUTTONDOWN"
        if (msgid == 0x0202):return "WM_LBUTTONUP"
        if (msgid == 0x0203):return "WM_LBUTTONDBLCLK"
        if (msgid == 0x0204):return "WM_RBUTTONDOWN"
        if (msgid == 0x0205):return "WM_RBUTTONUP"
        if (msgid == 0x0206):return "WM_RBUTTONDBLCLK"
        if (msgid == 0x0207):return "WM_MBUTTONDOWN"
        if (msgid == 0x0208):return "WM_MBUTTONUP"
        if (msgid == 0x0209):return "WM_MBUTTONDBLCLK"
        if (msgid == 0x020a):return "WM_MOUSEWHEEL"
        if (msgid == 0x020b):return "WM_XBUTTONDOWN"
        if (msgid == 0x020c):return "WM_XBUTTONUP"
        if (msgid == 0x020d):return "WM_XBUTTONDBLCLK"
        if (msgid == 0x020e):return "WM_UNDEF_0x020e"
        if (msgid == 0x020f):return "WM_UNDEF_0x020f"
        if (msgid == 0x0210):return "WM_PARENTNOTIFY"
        if (msgid == 0x0211):return "WM_ENTERMENULOOP"
        if (msgid == 0x0212):return "WM_EXITMENULOOP"
        if (msgid == 0x0213):return "WM_NEXTMENU"
        if (msgid == 0x0214):return "WM_SIZING"
        if (msgid == 0x0215):return "WM_CAPTURECHANGED"
        if (msgid == 0x0216):return "WM_MOVING"
        if (msgid == 0x0217):return "WM_UNDEF_0x0217"
        if (msgid == 0x0218):return "WM_POWERBROADCAST"
        if (msgid == 0x0219):return "WM_DEVICECHANGE"
        if (msgid == 0x021a):return "WM_UNDEF_0x021a"
        if (msgid == 0x021b):return "WM_UNDEF_0x021b"
        if (msgid == 0x021c):return "WM_UNDEF_0x021c"
        if (msgid == 0x021d):return "WM_UNDEF_0x021d"
        if (msgid == 0x021e):return "WM_UNDEF_0x021e"
        if (msgid == 0x021f):return "WM_UNDEF_0x021f"
        if (msgid == 0x0220):return "WM_MDICREATE"
        if (msgid == 0x0221):return "WM_MDIDESTROY"
        if (msgid == 0x0222):return "WM_MDIACTIVATE"
        if (msgid == 0x0223):return "WM_MDIRESTORE"
        if (msgid == 0x0224):return "WM_MDINEXT"
        if (msgid == 0x0225):return "WM_MDIMAXIMIZE"
        if (msgid == 0x0226):return "WM_MDITILE"
        if (msgid == 0x0227):return "WM_MDICASCADE"
        if (msgid == 0x0228):return "WM_MDIICONARRANGE"
        if (msgid == 0x0229):return "WM_MDIGETACTIVE"
        if (msgid == 0x022a):return "WM_DROPOBJECT"
        if (msgid == 0x022b):return "WM_QUERYDROPOBJECT"
        if (msgid == 0x022c):return "WM_BEGINDRAG"
        if (msgid == 0x022d):return "WM_DRAGLOOP"
        if (msgid == 0x022e):return "WM_DRAGSELECT"
        if (msgid == 0x022af):return "WM_DRAGMOVE"
        if (msgid == 0x0230):return "WM_MDISETMENU"
        if (msgid == 0x0231):return "WM_ENTERSIZEMOVE"
        if (msgid == 0x0232):return "WM_EXITSIZEMOVE"
        if (msgid == 0x0233):return "WM_DROPFILES"
        if (msgid == 0x0234):return "WM_MDIREFRESHMENU"
        if (msgid == 0x0235):return "WM_UNDEF_0x0235"
        if (msgid == 0x0236):return "WM_UNDEF_0x0236"
        if (msgid == 0x0237):return "WM_UNDEF_0x0237"
        if (msgid == 0x0238):return "WM_UNDEF_0x0238"
        if (msgid == 0x0239):return "WM_UNDEF_0x0239"
        if (msgid == 0x023a):return "WM_UNDEF_0x023a"
        if (msgid == 0x023b):return "WM_UNDEF_0x023b"
        if (msgid == 0x023c):return "WM_UNDEF_0x023c"
        if (msgid == 0x023d):return "WM_UNDEF_0x023d"
        if (msgid == 0x023e):return "WM_UNDEF_0x023e"
        if (msgid == 0x023f):return "WM_UNDEF_0x023f"
        if (msgid == 0x0240):return "WM_UNDEF_0x0240"
        if (msgid == 0x0241):return "WM_UNDEF_0x0241"
        if (msgid == 0x0242):return "WM_UNDEF_0x0242"
        if (msgid == 0x0243):return "WM_UNDEF_0x0243"
        if (msgid == 0x0244):return "WM_UNDEF_0x0244"
        if (msgid == 0x0245):return "WM_UNDEF_0x0245"
        if (msgid == 0x0246):return "WM_UNDEF_0x0246"
        if (msgid == 0x0247):return "WM_UNDEF_0x0247"
        if (msgid == 0x0248):return "WM_UNDEF_0x0248"
        if (msgid == 0x0249):return "WM_UNDEF_0x0249"
        if (msgid == 0x024a):return "WM_UNDEF_0x024a"
        if (msgid == 0x024b):return "WM_UNDEF_0x024b"
        if (msgid == 0x024c):return "WM_UNDEF_0x024c"
        if (msgid == 0x024d):return "WM_UNDEF_0x024d"
        if (msgid == 0x024e):return "WM_UNDEF_0x024e"
        if (msgid == 0x024f):return "WM_UNDEF_0x024f"
        if (msgid == 0x0250):return "WM_UNDEF_0x0250"
        if (msgid == 0x0251):return "WM_UNDEF_0x0251"
        if (msgid == 0x0252):return "WM_UNDEF_0x0252"
        if (msgid == 0x0253):return "WM_UNDEF_0x0253"
        if (msgid == 0x0254):return "WM_UNDEF_0x0254"
        if (msgid == 0x0255):return "WM_UNDEF_0x0255"
        if (msgid == 0x0256):return "WM_UNDEF_0x0256"
        if (msgid == 0x0257):return "WM_UNDEF_0x0257"
        if (msgid == 0x0258):return "WM_UNDEF_0x0258"
        if (msgid == 0x0259):return "WM_UNDEF_0x0259"
        if (msgid == 0x025a):return "WM_UNDEF_0x025a"
        if (msgid == 0x025b):return "WM_UNDEF_0x025b"
        if (msgid == 0x025c):return "WM_UNDEF_0x025c"
        if (msgid == 0x025d):return "WM_UNDEF_0x025d"
        if (msgid == 0x025e):return "WM_UNDEF_0x025e"
        if (msgid == 0x025f):return "WM_UNDEF_0x025f"
        if (msgid == 0x0260):return "WM_UNDEF_0x0260"
        if (msgid == 0x0261):return "WM_UNDEF_0x0261"
        if (msgid == 0x0262):return "WM_UNDEF_0x0262"
        if (msgid == 0x0263):return "WM_UNDEF_0x0263"
        if (msgid == 0x0264):return "WM_UNDEF_0x0264"
        if (msgid == 0x0265):return "WM_UNDEF_0x0265"
        if (msgid == 0x0266):return "WM_UNDEF_0x0266"
        if (msgid == 0x0267):return "WM_UNDEF_0x0267"
        if (msgid == 0x0268):return "WM_UNDEF_0x0268"
        if (msgid == 0x0269):return "WM_UNDEF_0x0269"
        if (msgid == 0x026a):return "WM_UNDEF_0x026a"
        if (msgid == 0x026b):return "WM_UNDEF_0x026b"
        if (msgid == 0x026c):return "WM_UNDEF_0x026c"
        if (msgid == 0x026d):return "WM_UNDEF_0x026d"
        if (msgid == 0x026e):return "WM_UNDEF_0x026e"
        if (msgid == 0x026f):return "WM_UNDEF_0x026f"
        if (msgid == 0x0270):return "WM_UNDEF_0x0270"
        if (msgid == 0x0271):return "WM_UNDEF_0x0271"
        if (msgid == 0x0272):return "WM_UNDEF_0x0272"
        if (msgid == 0x0273):return "WM_UNDEF_0x0273"
        if (msgid == 0x0274):return "WM_UNDEF_0x0274"
        if (msgid == 0x0275):return "WM_UNDEF_0x0275"
        if (msgid == 0x0276):return "WM_UNDEF_0x0276"
        if (msgid == 0x0277):return "WM_UNDEF_0x0277"
        if (msgid == 0x0278):return "WM_UNDEF_0x0278"
        if (msgid == 0x0279):return "WM_UNDEF_0x0279"
        if (msgid == 0x027a):return "WM_UNDEF_0x027a"
        if (msgid == 0x027b):return "WM_UNDEF_0x027b"
        if (msgid == 0x027c):return "WM_UNDEF_0x027c"
        if (msgid == 0x027d):return "WM_UNDEF_0x027d"
        if (msgid == 0x027e):return "WM_UNDEF_0x027e"
        if (msgid == 0x027f):return "WM_UNDEF_0x027f"
        if (msgid == 0x0280):return "WM_KANJIFIRST"
        if (msgid == 0x0281):return "WM_IME_SETCONTENT"
        if (msgid == 0x0282):return "WM_IME_NOTIFY"
        if (msgid == 0x0283):return "WM_IME_CONTROL"
        if (msgid == 0x0284):return "WM_IME_COMPOSITIONFULL"
        if (msgid == 0x0285):return "WM_IME_SELECT"
        if (msgid == 0x0286):return "WM_IME_CHAR"
        if (msgid == 0x0287):return "WM_IME_SYSTEM"
        if (msgid == 0x0288):return "WM_IME_REQUEST"
        if (msgid == 0x0289):return "WM_UNDEF_0x0289"
        if (msgid == 0x028a):return "WM_UNDEF_0x028a"
        if (msgid == 0x028b):return "WM_UNDEF_0x028b"
        if (msgid == 0x028c):return "WM_UNDEF_0x028c"
        if (msgid == 0x028d):return "WM_UNDEF_0x028d"
        if (msgid == 0x028e):return "WM_UNDEF_0x028e"
        if (msgid == 0x028f):return "WM_UNDEF_0x028f"
        if (msgid == 0x0290):return "WM_IME_KEYDOWN"
        if (msgid == 0x0291):return "WM_IME_KEYUP"
        if (msgid == 0x0292):return "WM_UNDEF_0x0292"
        if (msgid == 0x0293):return "WM_UNDEF_0x0293"
        if (msgid == 0x0294):return "WM_UNDEF_0x0294"
        if (msgid == 0x0295):return "WM_UNDEF_0x0295"
        if (msgid == 0x0296):return "WM_UNDEF_0x0296"
        if (msgid == 0x0297):return "WM_UNDEF_0x0297"
        if (msgid == 0x0298):return "WM_UNDEF_0x0298"
        if (msgid == 0x0299):return "WM_UNDEF_0x0299"
        if (msgid == 0x029a):return "WM_UNDEF_0x029a"
        if (msgid == 0x029b):return "WM_UNDEF_0x029b"
        if (msgid == 0x029c):return "WM_UNDEF_0x029c"
        if (msgid == 0x029d):return "WM_UNDEF_0x029d"
        if (msgid == 0x029e):return "WM_UNDEF_0x029e"
        if (msgid == 0x029f):return "WM_KANJILAST"
        if (msgid == 0x02a0):return "WM_NCMOUSEHOVER"
        if (msgid == 0x02a1):return "WM_MOUSEHOVER"
        if (msgid == 0x02a2):return "WM_NCMOUSELEAVE"
        if (msgid == 0x02a3):return "WM_MOUSELEAVE"
        if (msgid == 0x02a4):return "WM_UNDEF_0x02a4"
        if (msgid == 0x02a5):return "WM_UNDEF_0x02a5"
        if (msgid == 0x02a6):return "WM_UNDEF_0x02a6"
        if (msgid == 0x02a7):return "WM_UNDEF_0x02a7"
        if (msgid == 0x02a8):return "WM_UNDEF_0x02a8"
        if (msgid == 0x02a9):return "WM_UNDEF_0x02a9"
        if (msgid == 0x02aa):return "WM_UNDEF_0x02aa"
        if (msgid == 0x02ab):return "WM_UNDEF_0x02ab"
        if (msgid == 0x02ac):return "WM_UNDEF_0x02ac"
        if (msgid == 0x02ad):return "WM_UNDEF_0x02ad"
        if (msgid == 0x02ae):return "WM_UNDEF_0x02ae"
        if (msgid == 0x02af):return "WM_UNDEF_0x02af"
        if (msgid == 0x02b0):return "WM_UNDEF_0x02b0"
        if (msgid == 0x02b1):return "WM_UNDEF_0x02b1"
        if (msgid == 0x02b2):return "WM_UNDEF_0x02b2"
        if (msgid == 0x02b3):return "WM_UNDEF_0x02b3"
        if (msgid == 0x02b4):return "WM_UNDEF_0x02b4"
        if (msgid == 0x02b5):return "WM_UNDEF_0x02b5"
        if (msgid == 0x02b6):return "WM_UNDEF_0x02b6"
        if (msgid == 0x02b7):return "WM_UNDEF_0x02b7"
        if (msgid == 0x02b8):return "WM_UNDEF_0x02b8"
        if (msgid == 0x02b9):return "WM_UNDEF_0x02b9"
        if (msgid == 0x02ba):return "WM_UNDEF_0x02ba"
        if (msgid == 0x02bb):return "WM_UNDEF_0x02bb"
        if (msgid == 0x02bc):return "WM_UNDEF_0x02bc"
        if (msgid == 0x02bd):return "WM_UNDEF_0x02bd"
        if (msgid == 0x02be):return "WM_UNDEF_0x02be"
        if (msgid == 0x02bf):return "WM_UNDEF_0x02bf"
        if (msgid == 0x02c0):return "WM_UNDEF_0x02c0"
        if (msgid == 0x02c1):return "WM_UNDEF_0x02c1"
        if (msgid == 0x02c2):return "WM_UNDEF_0x02c2"
        if (msgid == 0x02c3):return "WM_UNDEF_0x02c3"
        if (msgid == 0x02c4):return "WM_UNDEF_0x02c4"
        if (msgid == 0x02c5):return "WM_UNDEF_0x02c5"
        if (msgid == 0x02c6):return "WM_UNDEF_0x02c6"
        if (msgid == 0x02c7):return "WM_UNDEF_0x02c7"
        if (msgid == 0x02c8):return "WM_UNDEF_0x02c8"
        if (msgid == 0x02c9):return "WM_UNDEF_0x02c9"
        if (msgid == 0x02ca):return "WM_UNDEF_0x02ca"
        if (msgid == 0x02cb):return "WM_UNDEF_0x02cb"
        if (msgid == 0x02cc):return "WM_UNDEF_0x02cc"
        if (msgid == 0x02cd):return "WM_UNDEF_0x02cd"
        if (msgid == 0x02ce):return "WM_UNDEF_0x02ce"
        if (msgid == 0x02cf):return "WM_UNDEF_0x02cf"
        if (msgid == 0x02d0):return "WM_UNDEF_0x02d0"
        if (msgid == 0x02d1):return "WM_UNDEF_0x02d1"
        if (msgid == 0x02d2):return "WM_UNDEF_0x02d2"
        if (msgid == 0x02d3):return "WM_UNDEF_0x02d3"
        if (msgid == 0x02d4):return "WM_UNDEF_0x02d4"
        if (msgid == 0x02d5):return "WM_UNDEF_0x02d5"
        if (msgid == 0x02d6):return "WM_UNDEF_0x02d6"
        if (msgid == 0x02d7):return "WM_UNDEF_0x02d7"
        if (msgid == 0x02d8):return "WM_UNDEF_0x02d8"
        if (msgid == 0x02d9):return "WM_UNDEF_0x02d9"
        if (msgid == 0x02da):return "WM_UNDEF_0x02da"
        if (msgid == 0x02db):return "WM_UNDEF_0x02db"
        if (msgid == 0x02dc):return "WM_UNDEF_0x02dc"
        if (msgid == 0x02dd):return "WM_UNDEF_0x02dd"
        if (msgid == 0x02de):return "WM_UNDEF_0x02de"
        if (msgid == 0x02df):return "WM_UNDEF_0x02df"
        if (msgid == 0x02e0):return "WM_UNDEF_0x02e0"
        if (msgid == 0x02e1):return "WM_UNDEF_0x02e1"
        if (msgid == 0x02e2):return "WM_UNDEF_0x02e2"
        if (msgid == 0x02e3):return "WM_UNDEF_0x02e3"
        if (msgid == 0x02e4):return "WM_UNDEF_0x02e4"
        if (msgid == 0x02e5):return "WM_UNDEF_0x02e5"
        if (msgid == 0x02e6):return "WM_UNDEF_0x02e6"
        if (msgid == 0x02e7):return "WM_UNDEF_0x02e7"
        if (msgid == 0x02e8):return "WM_UNDEF_0x02e8"
        if (msgid == 0x02e9):return "WM_UNDEF_0x02e9"
        if (msgid == 0x02ea):return "WM_UNDEF_0x02ea"
        if (msgid == 0x02eb):return "WM_UNDEF_0x02eb"
        if (msgid == 0x02ec):return "WM_UNDEF_0x02ec"
        if (msgid == 0x02ed):return "WM_UNDEF_0x02ed"
        if (msgid == 0x02ee):return "WM_UNDEF_0x02ee"
        if (msgid == 0x02ef):return "WM_UNDEF_0x02ef"
        if (msgid == 0x02f0):return "WM_UNDEF_0x02f0"
        if (msgid == 0x02f1):return "WM_UNDEF_0x02f1"
        if (msgid == 0x02f2):return "WM_UNDEF_0x02f2"
        if (msgid == 0x02f3):return "WM_UNDEF_0x02f3"
        if (msgid == 0x02f4):return "WM_UNDEF_0x02f4"
        if (msgid == 0x02f5):return "WM_UNDEF_0x02f5"
        if (msgid == 0x02f6):return "WM_UNDEF_0x02f6"
        if (msgid == 0x02f7):return "WM_UNDEF_0x02f7"
        if (msgid == 0x02f8):return "WM_UNDEF_0x02f8"
        if (msgid == 0x02f9):return "WM_UNDEF_0x02f9"
        if (msgid == 0x02fa):return "WM_UNDEF_0x02fa"
        if (msgid == 0x02fb):return "WM_UNDEF_0x02fb"
        if (msgid == 0x02fc):return "WM_UNDEF_0x02fc"
        if (msgid == 0x02fd):return "WM_UNDEF_0x02fd"
        if (msgid == 0x02fe):return "WM_UNDEF_0x02fe"
        if (msgid == 0x02ff):return "WM_UNDEF_0x02ff"
        if (msgid == 0x0300):return "WM_CUT"
        if (msgid == 0x0301):return "WM_COPY"
        if (msgid == 0x0302):return "WM_PASTE"
        if (msgid == 0x0303):return "WM_CLEAR"
        if (msgid == 0x0304):return "WM_UNDO"
        if (msgid == 0x0305):return "WM_RENDERFORMAT"
        if (msgid == 0x0306):return "WM_RENDERALLFORMATS"
        if (msgid == 0x0307):return "WM_DESTROYCLIPBOARD"
        if (msgid == 0x0308):return "WM_DRAWCLIPBOARD"
        if (msgid == 0x0309):return "WM_PAINTCLIPBOARD"
        if (msgid == 0x030a):return "WM_VSCROLLCLIPBOARD"
        if (msgid == 0x030b):return "WM_SIZECLIPBOARD"
        if (msgid == 0x030c):return "WM_ASKCBFORMATNAME"
        if (msgid == 0x030d):return "WM_CHANGECBCHAIN"
        if (msgid == 0x030e):return "WM_HSCROLLCLIPBOARD"
        if (msgid == 0x030f):return "WM_QUERYNEWPALETTE"
        if (msgid == 0x0310):return "WM_PALETTEISCHANGING"
        if (msgid == 0x0311):return "WM_PALETTECHANGED"
        if (msgid == 0x0312):return "WM_HOTKEY"
        if (msgid == 0x0313):return "WM_HOOKMSG"
        if (msgid == 0x0314):return "WM_SYSMENU"
        if (msgid == 0x0315):return "WM_EXITPROCESS"
        if (msgid == 0x0316):return "WM_WAKETHREAD"
        if (msgid == 0x0317):return "WM_PRINT"
        if (msgid == 0x0318):return "WM_PRINTCLIENT"
        if (msgid == 0x0319):return "WM_APPCOMMAND"
        if (msgid == 0x031a):return "WM_THEMECHANGED"
        if (msgid == 0x031b):return "WM_UAHINIT"
        if (msgid == 0x031c):return "WM_UNDEF_0x031c"
        if (msgid == 0x031d):return "WM_UNDEF_0x031d"
        if (msgid == 0x031e):return "WM_UNDEF_0x031e"
        if (msgid == 0x031f):return "WM_UNDEF_0x031f"
        if (msgid == 0x0320):return "WM_UNDEF_0x0320"
        if (msgid == 0x0321):return "WM_UNDEF_0x0321"
        if (msgid == 0x0322):return "WM_UNDEF_0x0322"
        if (msgid == 0x0323):return "WM_UNDEF_0x0323"
        if (msgid == 0x0324):return "WM_UNDEF_0x0324"
        if (msgid == 0x0325):return "WM_UNDEF_0x0325"
        if (msgid == 0x0326):return "WM_UNDEF_0x0326"
        if (msgid == 0x0327):return "WM_UNDEF_0x0327"
        if (msgid == 0x0328):return "WM_UNDEF_0x0328"
        if (msgid == 0x0329):return "WM_UNDEF_0x0329"
        if (msgid == 0x032a):return "WM_UNDEF_0x032a"
        if (msgid == 0x032b):return "WM_UNDEF_0x032b"
        if (msgid == 0x032c):return "WM_UNDEF_0x032c"
        if (msgid == 0x032d):return "WM_UNDEF_0x032d"
        if (msgid == 0x032e):return "WM_UNDEF_0x032e"
        if (msgid == 0x032f):return "WM_UNDEF_0x032f"
        if (msgid == 0x0330):return "WM_UNDEF_0x0330"
        if (msgid == 0x0331):return "WM_UNDEF_0x0331"
        if (msgid == 0x0332):return "WM_UNDEF_0x0332"
        if (msgid == 0x0333):return "WM_UNDEF_0x0333"
        if (msgid == 0x0334):return "WM_UNDEF_0x0334"
        if (msgid == 0x0335):return "WM_UNDEF_0x0335"
        if (msgid == 0x0336):return "WM_UNDEF_0x0336"
        if (msgid == 0x0337):return "WM_UNDEF_0x0337"
        if (msgid == 0x0338):return "WM_UNDEF_0x0338"
        if (msgid == 0x0339):return "WM_UNDEF_0x0339"
        if (msgid == 0x033a):return "WM_UNDEF_0x033a"
        if (msgid == 0x033b):return "WM_UNDEF_0x033b"
        if (msgid == 0x033c):return "WM_UNDEF_0x033c"
        if (msgid == 0x033d):return "WM_UNDEF_0x033d"
        if (msgid == 0x033e):return "WM_UNDEF_0x033e"
        if (msgid == 0x033f):return "WM_UNDEF_0x033f"
        if (msgid == 0x0340):return "WM_NOTIFYWOW"
        if (msgid == 0x0341):return "WM_UNDEF_0x0341"
        if (msgid == 0x0342):return "WM_UNDEF_0x0342"
        if (msgid == 0x0343):return "WM_UNDEF_0x0343"
        if (msgid == 0x0344):return "WM_UNDEF_0x0344"
        if (msgid == 0x0345):return "WM_UNDEF_0x0345"
        if (msgid == 0x0346):return "WM_UNDEF_0x0346"
        if (msgid == 0x0347):return "WM_UNDEF_0x0347"
        if (msgid == 0x0348):return "WM_UNDEF_0x0348"
        if (msgid == 0x0349):return "WM_UNDEF_0x0349"
        if (msgid == 0x034a):return "WM_UNDEF_0x034a"
        if (msgid == 0x034b):return "WM_UNDEF_0x034b"
        if (msgid == 0x034c):return "WM_UNDEF_0x034c"
        if (msgid == 0x034d):return "WM_UNDEF_0x034d"
        if (msgid == 0x034e):return "WM_UNDEF_0x034e"
        if (msgid == 0x034f):return "WM_UNDEF_0x034f"
        if (msgid == 0x0350):return "WM_UNDEF_0x0350"
        if (msgid == 0x0351):return "WM_UNDEF_0x0351"
        if (msgid == 0x0352):return "WM_UNDEF_0x0352"
        if (msgid == 0x0353):return "WM_UNDEF_0x0353"
        if (msgid == 0x0354):return "WM_UNDEF_0x0354"
        if (msgid == 0x0355):return "WM_UNDEF_0x0355"
        if (msgid == 0x0356):return "WM_UNDEF_0x0356"
        if (msgid == 0x0357):return "WM_UNDEF_0x0357"
        if (msgid == 0x0358):return "WM_UNDEF_0x0358"
        if (msgid == 0x0359):return "WM_UNDEF_0x0359"
        if (msgid == 0x035a):return "WM_UNDEF_0x035a"
        if (msgid == 0x035b):return "WM_UNDEF_0x035b"
        if (msgid == 0x035c):return "WM_UNDEF_0x035c"
        if (msgid == 0x035d):return "WM_UNDEF_0x035d"
        if (msgid == 0x035e):return "WM_UNDEF_0x035e"
        if (msgid == 0x035f):return "WM_UNDEF_0x035f"
        if (msgid == 0x0360):return "WM_QUERYAFXWNDPROC"
        if (msgid == 0x0361):return "WM_SIZEPARENT"
        if (msgid == 0x0362):return "WM_SETMESSAGESTRING"
        if (msgid == 0x0363):return "WM_IDLEUPDATECMDUI"
        if (msgid == 0x0364):return "WM_INITIALUPDATE"
        if (msgid == 0x0365):return "WM_COMMANDHELP"
        if (msgid == 0x0366):return "WM_HELPHITTEST"
        if (msgid == 0x0367):return "WM_EXITHELPMODE"
        if (msgid == 0x0368):return "WM_RECALCPARENT"
        if (msgid == 0x0369):return "WM_SIZECHILD"
        if (msgid == 0x036A):return "WM_KICKIDLE"
        if (msgid == 0x036B):return "WM_QUERYCENTERWND"
        if (msgid == 0x036C):return "WM_DISABLEMODAL"
        if (msgid == 0x036D):return "WM_FLOATSTATUS"
        if (msgid == 0x036E):return "WM_ACTIVATETOPLEVEL"
        if (msgid == 0x036F):return "WM_QUERY3DCONTROLS"
        if (msgid == 0x0370):return "WM_UNDEF_0x0370"
        if (msgid == 0x0371):return "WM_UNDEF_0x0371"
        if (msgid == 0x0372):return "WM_UNDEF_0x0372"
        if (msgid == 0x0373):return "WM_SOCKET_NOTIFY"
        if (msgid == 0x0374):return "WM_SOCKET_DEAD"
        if (msgid == 0x0375):return "WM_POPMESSAGESTRING"
        if (msgid == 0x0376):return "WM_OCC_LOADFROMSTREAM"
        if (msgid == 0x0377):return "WM_OCC_LOADFROMSTORAGE"
        if (msgid == 0x0378):return "WM_OCC_INITNEW"
        if (msgid == 0x0379):return "WM_QUEUE_SENTINEL"
        if (msgid == 0x037A):return "WM_OCC_LOADFROMSTREAM_EX"
        if (msgid == 0x037B):return "WM_OCC_LOADFROMSTORAGE_EX"
        if (msgid == 0x037c):return "WM_UNDEF_0x037c"
        if (msgid == 0x037d):return "WM_UNDEF_0x037d"
        if (msgid == 0x037e):return "WM_UNDEF_0x037e"
        if (msgid == 0x037f):return "WM_UNDEF_0x037f"
        if (msgid == 0x0380):return "WM_PENWINFIRST"
        if (msgid == 0x0381):return "WM_RCRESULT"
        if (msgid == 0x0382):return "WM_HOOKRCRESULT"
        if (msgid == 0x0383):return "WM_GLOBALRCCHANGE"
        if (msgid == 0x0384):return "WM_SKB"
        if (msgid == 0x0385):return "WM_HEDITCTL"
        if (msgid == 0x0386):return "WM_UNDEF_0x0386"
        if (msgid == 0x0387):return "WM_UNDEF_0x0387"
        if (msgid == 0x0388):return "WM_UNDEF_0x0388"
        if (msgid == 0x0389):return "WM_UNDEF_0x0389"
        if (msgid == 0x038a):return "WM_UNDEF_0x038a"
        if (msgid == 0x038b):return "WM_UNDEF_0x038b"
        if (msgid == 0x038c):return "WM_UNDEF_0x038c"
        if (msgid == 0x038d):return "WM_UNDEF_0x038d"
        if (msgid == 0x038e):return "WM_UNDEF_0x038e"
        if (msgid == 0x038f):return "WM_PENWINLAST"
        if (msgid == 0x0390):return "WM_COALESCE_FIRST"
        if (msgid == 0x0391):return "WM_UNDEF_0x0391"
        if (msgid == 0x0392):return "WM_UNDEF_0x0392"
        if (msgid == 0x0393):return "WM_UNDEF_0x0393"
        if (msgid == 0x0394):return "WM_UNDEF_0x0394"
        if (msgid == 0x0395):return "WM_UNDEF_0x0395"
        if (msgid == 0x0396):return "WM_UNDEF_0x0396"
        if (msgid == 0x0397):return "WM_UNDEF_0x0397"
        if (msgid == 0x0398):return "WM_UNDEF_0x0398"
        if (msgid == 0x0399):return "WM_UNDEF_0x0399"
        if (msgid == 0x039a):return "WM_UNDEF_0x039a"
        if (msgid == 0x039b):return "WM_UNDEF_0x039b"
        if (msgid == 0x039c):return "WM_UNDEF_0x039c"
        if (msgid == 0x039d):return "WM_UNDEF_0x039d"
        if (msgid == 0x039e):return "WM_UNDEF_0x039e"
        if (msgid == 0x039f):return "WM_COALESCE_LAST"
        if (msgid == 0x03a0):return "MM_JOY1MOVE"
        if (msgid == 0x03a1):return "MM_JOY2MOVE"
        if (msgid == 0x03a2):return "MM_JOY1ZMOVE"
        if (msgid == 0x03a3):return "MM_JOY2ZMOVE"
        if (msgid == 0x03a4):return "WM_UNDEF_0x03a4"
        if (msgid == 0x03a5):return "WM_UNDEF_0x03a5"
        if (msgid == 0x03a6):return "WM_UNDEF_0x03a6"
        if (msgid == 0x03a7):return "WM_UNDEF_0x03a7"
        if (msgid == 0x03a8):return "WM_UNDEF_0x03a8"
        if (msgid == 0x03a9):return "WM_UNDEF_0x03a9"
        if (msgid == 0x03aa):return "WM_UNDEF_0x03aa"
        if (msgid == 0x03ab):return "WM_UNDEF_0x03ab"
        if (msgid == 0x03ac):return "WM_UNDEF_0x03ac"
        if (msgid == 0x03ad):return "WM_UNDEF_0x03ad"
        if (msgid == 0x03ae):return "WM_UNDEF_0x03ae"
        if (msgid == 0x03af):return "WM_UNDEF_0x03af"
        if (msgid == 0x03b0):return "WM_UNDEF_0x03b0"
        if (msgid == 0x03b1):return "WM_UNDEF_0x03b1"
        if (msgid == 0x03b2):return "WM_UNDEF_0x03b2"
        if (msgid == 0x03b3):return "WM_UNDEF_0x03b3"
        if (msgid == 0x03b4):return "WM_UNDEF_0x03b4"
        if (msgid == 0x03b5):return "MM_JOY1BUTTONDOWN"
        if (msgid == 0x03b6):return "MM_JOY2BUTTONDOWN"
        if (msgid == 0x03b7):return "MM_JOY1BUTTONUP"
        if (msgid == 0x03b8):return "MM_JOY2BUTTONUP"
        if (msgid == 0x03b9):return "MM_MCINOTIFY"
        if (msgid == 0x03ba):return "WM_UNDEF_0x03ba"
        if (msgid == 0x03bb):return "MM_WOM_OPEN"
        if (msgid == 0x03bc):return "MM_WOM_CLOSE"
        if (msgid == 0x03bd):return "MM_WOM_DONE"
        if (msgid == 0x03be):return "MM_WIM_OPEN"
        if (msgid == 0x03bf):return "MM_WIM_CLOSE"
        if (msgid == 0x03c0):return "MM_WIM_DATA"
        if (msgid == 0x03c1):return "MM_MIM_OPEN"
        if (msgid == 0x03c2):return "MM_MIM_CLOSE"
        if (msgid == 0x03c3):return "MM_MIM_DATA"
        if (msgid == 0x03c4):return "MM_MIM_LONGDATA"
        if (msgid == 0x03c5):return "MM_MIM_ERROR"
        if (msgid == 0x03c6):return "MM_MIM_LONGERROR"
        if (msgid == 0x03c7):return "MM_MOM_OPEN"
        if (msgid == 0x03c8):return "MM_MOM_CLOSE"
        if (msgid == 0x03c9):return "MM_MOM_DONE"
        if (msgid == 0x03ca):return "WM_UNDEF_0x03ca"
        if (msgid == 0x03cb):return "WM_UNDEF_0x03cb"
        if (msgid == 0x03cc):return "WM_UNDEF_0x03cc"
        if (msgid == 0x03cd):return "WM_UNDEF_0x03cd"
        if (msgid == 0x03ce):return "WM_UNDEF_0x03ce"
        if (msgid == 0x03cf):return "WM_UNDEF_0x03cf"
        if (msgid == 0x03d0):return "WM_UNDEF_0x03d0"
        if (msgid == 0x03d1):return "WM_UNDEF_0x03d1"
        if (msgid == 0x03d2):return "WM_UNDEF_0x03d2"
        if (msgid == 0x03d3):return "WM_UNDEF_0x03d3"
        if (msgid == 0x03d4):return "WM_UNDEF_0x03d4"
        if (msgid == 0x03d5):return "WM_UNDEF_0x03d5"
        if (msgid == 0x03d6):return "WM_UNDEF_0x03d6"
        if (msgid == 0x03d7):return "WM_UNDEF_0x03d7"
        if (msgid == 0x03d8):return "WM_UNDEF_0x03d8"
        if (msgid == 0x03d9):return "WM_UNDEF_0x03d9"
        if (msgid == 0x03da):return "WM_UNDEF_0x03da"
        if (msgid == 0x03db):return "WM_UNDEF_0x03db"
        if (msgid == 0x03dc):return "WM_UNDEF_0x03dc"
        if (msgid == 0x03dd):return "WM_UNDEF_0x03dd"
        if (msgid == 0x03de):return "WM_UNDEF_0x03de"
        if (msgid == 0x03df):return "WM_MM_RESERVED_LAST"
        if (msgid == 0x3E0):return "WM_DDE_INITIATE"
        if (msgid == 0x3E1):return "WM_DDE_TERMINATE"
        if (msgid == 0x3E2):return "WM_DDE_ADVISE"
        if (msgid == 0x3E3):return "WM_DDE_UNADVISE"
        if (msgid == 0x3E4):return "WM_DDE_ACK"
        if (msgid == 0x3E5):return "WM_DDE_DATA"
        if (msgid == 0x3E6):return "WM_DDE_REQUEST"
        if (msgid == 0x3E7):return "WM_DDE_POKE"
        if (msgid == 0x3E8):return "WM_DDE_EXECUTE"
        if (msgid == 0x03e9):return "WM_UNDEF_0x03e9"
        if (msgid == 0x03ea):return "WM_UNDEF_0x03ea"
        if (msgid == 0x03eb):return "WM_UNDEF_0x03eb"
        if (msgid == 0x03ec):return "WM_UNDEF_0x03ec"
        if (msgid == 0x03ed):return "WM_UNDEF_0x03ed"
        if (msgid == 0x03ee):return "WM_UNDEF_0x03ee"
        if (msgid == 0x03ef):return "WM_UNDEF_0x03ef"
        if (msgid == 0x03f0):return "WM_CBT_RESERVED_FIRST"
        if (msgid == 0x03f1):return "WM_UNDEF_0x03f1"
        if (msgid == 0x03f2):return "WM_UNDEF_0x03f2"
        if (msgid == 0x03f3):return "WM_UNDEF_0x03f3"
        if (msgid == 0x03f4):return "WM_UNDEF_0x03f4"
        if (msgid == 0x03f5):return "WM_UNDEF_0x03f5"
        if (msgid == 0x03f6):return "WM_UNDEF_0x03f6"
        if (msgid == 0x03f7):return "WM_UNDEF_0x03f7"
        if (msgid == 0x03f8):return "WM_UNDEF_0x03f8"
        if (msgid == 0x03f9):return "WM_UNDEF_0x03f9"
        if (msgid == 0x03fa):return "WM_UNDEF_0x03fa"
        if (msgid == 0x03fb):return "WM_UNDEF_0x03fb"
        if (msgid == 0x03fc):return "WM_UNDEF_0x03fc"
        if (msgid == 0x03fd):return "WM_UNDEF_0x03fd"
        if (msgid == 0x03fe):return "WM_UNDEF_0x03fe"
        if (msgid == 0x03ff):return "WM_CBT_RESERVED_LAST"
        if (msgid == 0x0400):return "WM_USER"

        return "WM_USER_%#04lx" %(msgid)

    def CheckMSGEntry_attr(self, entry):
        if (entry == BADADDR):
            return 0
        if (idaapi.get_dword(entry + 8) > 65535):
            return 0
        if (idaapi.get_dword(entry + 12) > 65535):
            return 0
        if (self.getAword(entry + 16) > 100): #Sig
            return 0

        return 1
        
    def getAword(self, addr, offset=0):
         if (__EA64__):
            return idaapi.get_qword(addr+offset*8)
         else:
            return idaapi.get_dword(addr+offset*4)
            
    def get_pfn(self, addr):
        if (__EA64__):
            return idaapi.get_qword(addr+24)
        else:
            return idaapi.get_dword(addr+20)
            
    def CheckMSGMAP(self, addr):
        addrGetThisMessageMap = self.getAword(addr, 0)
        addrMsgEntry = self.getAword(addr, 1)
                
        if (self.CheckMSGEntry_attr(addrMsgEntry) == 0):
            return 0
            
        if (self.cmax == 0 or self.rmax == 0):    
            snum = ida_segment.get_segm_qty()
            
            for i in range(0, snum):
                s = ida_segment.getnseg(i)
                segname = ida_segment.get_segm_name(s)

                if (segname == ".text"):
                  self.cmin = s.start_ea
                  self.cmax = s.end_ea

                if (segname == ".rdata"):
                  self.rmin = s.start_ea
                  self.rmax = s.end_ea

        if (self.cmin == self.cmax or self.cmax == 0):
            return 0
        if (self.rmin == self.rmax or self.rmax == 0):
            return 0

        if (addrGetThisMessageMap < self.cmin or addrGetThisMessageMap > self.cmax):
            return 0
        if (addrMsgEntry < self.rmin or addrMsgEntry > self.rmax):
            return 0

        if (idaapi.get_dword(addrMsgEntry + 0) == 0 and
            (idaapi.get_dword(addrMsgEntry + 4) != 0 or
            idaapi.get_dword(addrMsgEntry + 8) != 0 or
            idaapi.get_dword(addrMsgEntry + 12) != 0 or
            self.getAword(addrMsgEntry + 16) != 0 or
            self.get_pfn(addrMsgEntry) != 0)):
                return 0
        
        if (idaapi.get_name(addr) == ""):
            if (idaapi.get_name(addrGetThisMessageMap) == ""):
                return 0
            return -1

        if (idaapi.get_name(addrGetThisMessageMap)[0:18] == "?GetThisMessageMap"):
            return 1

        while(addrMsgEntry != BADADDR):
            if (idaapi.get_dword(addrMsgEntry + 0) == 0 and
                idaapi.get_dword(addrMsgEntry + 4) == 0 and
                idaapi.get_dword(addrMsgEntry + 8) == 0 and
                idaapi.get_dword(addrMsgEntry + 12) == 0 and
                self.getAword(addrMsgEntry + 16) == 0 and
                self.get_pfn(addrMsgEntry) == 0):
                return 1
            
            if (self.CheckMSGEntry_attr(addrMsgEntry) == 0):
                return 0

            if (addrGetThisMessageMap < self.cmin or addrGetThisMessageMap > self.cmax):
                return 0
            
            msgfun_addr = self.get_pfn(addrMsgEntry)
            if (msgfun_addr < self.cmin or msgfun_addr > self.cmax):
                return 0
            
            addrMsgEntry = addrMsgEntry + self.MSGStructSize
        
        return 0
    
    def MakeOffset(self, addr):
        if (__EA64__):
            create_data(addr, FF_0OFF|FF_QWORD, 8, ida_idaapi.BADADDR)
        else:
            create_data(addr, FF_0OFF|FF_DWORD, 4, ida_idaapi.BADADDR)

    def MakeAfxMSG(self, addr):
        if (__EA64__):
            self.MakeOffset(addr)
            self.MakeOffset(addr+8)
        else:
            self.MakeOffset(addr)
            self.MakeOffset(addr+4)
            
    def MakeMSG_ENTRY(self, addr):
        msgmapSize = 0
        addrGetThisMessageMap = self.getAword(addr, 0)
        addrMsgEntry = self.getAword(addr, 1)
        
        self.MakeAfxMSG(addr)
        if (Name(addr) == ("off_%lX" % (addr)) or Name(addr) == ""):
            MakeName(addr, "msgEntries_%lX" % (addr))
    
        pEntry = addrMsgEntry
        while(idaapi.get_dword(pEntry) != 0):
            
            MakeUnknown(pEntry, self.MSGStructSize, DELIT_SIMPLE)
            if (MakeStructEx(pEntry, self.MSGStructSize, "AFX_MSGMAP_ENTRY") == 0):
                print "Create AFX_MSGMAP_ENTRY failed at %X" % (pEntry)
                return 0
            
            msgName = self.GetMsgName(Dword(pEntry + 0))
            
            str_funcmt = "MSG function:" + msgName
            str_funcmt += "\n   MSG:  " + hex(Dword(pEntry + 0)).upper()
            str_funcmt += "\n  Code:  " + str(Dword(pEntry + 4))
            str_funcmt += "\n    Id:  " + str(Dword(pEntry + 8)) + " - " + str(Dword(pEntry + 12))
            		
            func_startEa = self.get_pfn(pEntry)
            pfn = ida_funcs.get_func(func_startEa)
            if (pfn is None):
                MakeUnkn(func_startEa, DELIT_SIMPLE)
                ida_funcs.add_func(func_startEa)
                pfn = ida_funcs.get_func(func_startEa)
                
            ida_funcs.set_func_cmt(pfn, str_funcmt, 0)
            oldname = ida_funcs.get_func_name(func_startEa)
            if (oldname == "sub_%lX" % (func_startEa)):
                newname = ""
                if (Dword(pEntry + 8) == Dword(pEntry + 12)):
                    if (Dword(pEntry + 8) != 0):
                        newname = "On_%s_%X_%u" % (msgName, func_startEa, Dword(pEntry + 8))
                    else:
                        newname = "On_%s_%X" % (msgName, func_startEa)
                else:
                    newname = "On_%s_%X_%u_to_%u" % (msgName, func_startEa, Dword(pEntry + 8), Dword(pEntry + 12))
                    
                MakeName(func_startEa, newname)
            
            pEntry = pEntry + self.MSGStructSize
        
        #AFX_MSG_END
        MakeUnknown(pEntry, self.MSGStructSize, DELIT_SIMPLE)
        MakeStructEx(pEntry, self.MSGStructSize, "AFX_MSGMAP_ENTRY")
        msgmapSize = pEntry - addrMsgEntry + self.MSGStructSize
        return msgmapSize
    
    # Search All AFX_MSGMAP
    def Search_MSGMAP(self):
        snum = ida_segment.get_segm_qty()
        
        for i in range(0, snum):
            s = ida_segment.getnseg(i)
            segname = ida_segment.get_segm_name(s)

            if (segname == ".text"):
              self.cmin = s.start_ea
              self.cmax = s.end_ea

            if (segname == ".rdata"):
              self.rmin = s.start_ea
              self.rmax = s.end_ea

        if (self.cmin == self.cmax or self.cmax == 0):
            return 0
        if (self.rmin == self.rmax or self.rmax == 0):
            return 0  

        totalCount = 0
        parseCount = 0
        addr = self.rmin
        
        try:
            idaapi.show_wait_box("Search for AFX_MSGMAP...")
            values = list()
            while(addr != BADADDR):
                ret = self.CheckMSGMAP(addr)
                MSGMAPSize = 0
                if (ret > 0):
                    totalCount += 1
                    strfind = "Find AFX_MSGMAP at 0x%X\n" % (addr)
                    #msg(strfind)
                    replace_wait_box(strfind)
                    
                    if (Name(addr) == "off_%lX" % (addr)):
                        parseCount += 1
                    
                    MSGMAPSize = self.MakeMSG_ENTRY(addr)
                              
                    value = [
                        totalCount-1,
                        addr,
                        Name(addr),
                        (MSGMAPSize-self.MSGStructSize)/self.MSGStructSize
                    ]
                    values.append(value)    

                addr += MSGMAPSize + self.USize

                MSGMAPSize = 0
                if (addr > self.rmax):
                    break
        finally:
            idaapi.hide_wait_box()
            
        c = AFXMSGMAPSearchResultChooser("SearchAFX_MSGMAP results", values)
        r = c.show()
        msg("===== Search complete, total %lu, new resolution %lu=====\n" % (totalCount, parseCount))
            
try:
    class Kp_Menu_Context(idaapi.action_handler_t):

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            try:
                if ctx.form_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
            except:
                # Add exception for main menu on >= IDA 7.0
                return idaapi.AST_ENABLE_ALWAYS
            
    # context menu for Patcher
    class Kp_MC_Make_MSGMAP(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.make_msgmap()
            return 1

    # context menu for Fill Range
    class Kp_MC_Find_MSGMAP(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search_msgmap()
            return 1
except:
    pass



# hooks for popup menu
class Hooks(idaapi.UI_Hooks):
    if idaapi.IDA_SDK_VERSION >= 700:
        # IDA >= 700 right click widget popup
        def finish_populating_widget_popup(self, form, popup):
            if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Make_MSGMAP.get_name(), 'AFX_MSGMAP/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Find_MSGMAP.get_name(), 'AFX_MSGMAP/')
                except:
                    pass
    else:
        # IDA < 700 right click popup
        def finish_populating_tform_popup(self, form, popup):
            # We'll add our action to all "IDA View-*"s.
            # If we wanted to add it only to "IDA View-A", we could
            # also discriminate on the widget's title:
            #
            #  if idaapi.get_tform_title(form) == "IDA View-A":
            #      ...
            #
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Patcher.get_name(), 'AFX_MSGMAP/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Fill_Range.get_name(), 'AFX_MSGMAP/')
                except:
                    pass
    
class AfxMsgMapPlugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "AFX_MSGMAP identify"
    help = ""
    wanted_name = "AFX_MSGMAP Find"
    wanted_hotkey = ""
    
    def __init__(self):
        self.afxmsgmap = AfxMSGMap()
        
    def init(self):
        global plugin_initialized
        # register popup menu handlers
        try:
            Kp_MC_Make_MSGMAP.register(self, "Make as AFX_MSGMAP")
            Kp_MC_Find_MSGMAP.register(self, "Search AFX_MSGMAP")
        except:
            pass
            
        """    
        if plugin_initialized == False:
            plugin_initialized = True
            if idaapi.IDA_SDK_VERSION >= 700:
                # Add menu IDA >= 7.0
                idaapi.attach_action_to_menu("Edit/Afx MSGMAP/Make AFX_MSGMAP", Kp_MC_Make_MSGMAP.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Afx MSGMAP/Search AFX_MSGMAP", Kp_MC_Find_MSGMAP.get_name(), idaapi.SETMENU_APP)
        """
        
        # setup popup menu
        self.hooks = Hooks()
        self.hooks.hook()
        self.afxmsgmap.AddMSGMAPStruct()
        
        if idaapi.init_hexrays_plugin():
            print "AFX_MSGMAP plugin installed"
            print "    write by snow<85703533>"
            addon = idaapi.addon_info_t()
            addon.id = "snow.afxmsgmap"
            addon.name = "AfxMSGMap"
            addon.producer = "Snow"
            addon.url = ""
            addon.version = "7.00"
            idaapi.register_addon(addon)
            return idaapi.PLUGIN_KEEP
        
        return idaapi.PLUGIN_SKIP

    def run(self, arg=0):
        return

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None

    # null handler
    def make_msgmap(self):
        address = idc.ScreenEA()
        if (self.afxmsgmap.CheckMSGMAP(address) > 0):
            self.afxmsgmap.MakeMSG_ENTRY(address)
        else:
            msg("This is not a AFX_MSGMAP")

    # handler for About menu
    def search_msgmap(self):
        self.afxmsgmap.Search_MSGMAP() 
        
def PLUGIN_ENTRY():
    return AfxMsgMapPlugin_t()
