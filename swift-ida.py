import ida_idaapi
import ida_kernwin
import ida_hexrays
import idc

action_names = []
call_convs = ["swiftcall", "golang", "fastcall"]


class SwiftIDA(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "SwiftIDA Plugin"
    help = "SwiftIDA Plugin"
    wanted_name = "SwiftIDA"
    wanted_hotkey = ""
    dialog = None

    def init(self):
        global action_names, call_convs

        for call_conv in call_convs:
            action_name = f"SwiftIDA:set_call_conv_{call_conv}"
            action = ida_kernwin.action_desc_t(
                action_name,
                f"Mark {call_conv}",
                generic_handler(
                    lambda ea, c=call_conv: self.convert_to_call_conv(ea, c)
                ),
            )
            ida_kernwin.register_action(action)
            action_names.append(action_name)

        for i in range(2, 9):
            action_name = f"SwiftIDA:make_multi_return_{i}"
            action = ida_kernwin.action_desc_t(
                action_name,
                f"Make return tuple{i}",
                generic_handler(lambda ea, i=i: self.make_multi_return(ea, i)),
            )
            ida_kernwin.register_action(action)
            action_names.append(action_name)

        self.ui_hooks = SwiftIDAUIHooks()
        self.ui_hooks.hook()

        return ida_idaapi.PLUGIN_KEEP

    def parse_current_func_type(self, ea):
        type: str = idc.get_type(ea)
        if type is None:
            ida_kernwin.warning("The selected item is not a function definition!")
            return None, None, None
        print(f">>>SwiftIDA: Original type: {type}")

        base, args = type[:-1].split("(", 1)

        base_split = base.split(" ", 1)
        ret_type = base_split[0]

        if len(base_split) == 2:
            base = base_split[1]
        else:
            base = ""

        return ret_type, base, args

    def update_current_func_type(self, ea, ret_type: str, base: str, args: str):

        new_type = " ".join(
            part for part in [ret_type, base, f"func({args})"] if part != ""
        )
        print(f">>>SwiftIDA: New type: {new_type}")

        result = idc.SetType(ea, new_type)
        if result != 1:
            raise Exception("Failed to set type")

        print(f">>>SwiftIDA: Type changed successfully")

    def convert_to_call_conv(self, ea, call_conv) -> bool:
        global call_convs

        ret_type, base, args = self.parse_current_func_type(ea)
        if ret_type is None or base is None or args is None:
            return False

        for item in call_convs:
            base = base.replace("__" + item, "")

        base = " ".join(part for part in ["__" + call_conv, base] if part != "")

        self.update_current_func_type(ea, ret_type, base, args)
        return True

    def make_multi_return(self, ea, i: int) -> bool:
        struct_name = f"swiftida_tuple{i}"
        if idc.get_struc_id(struct_name) == idc.BADADDR:
            struct_id = idc.add_struc(-1, struct_name, 0)
            for j in range(i):
                idc.add_struc_member(struct_id, f"o{j}", -1, idc.FF_QWORD, -1, 8)
            print(f">>>SwiftIDA: Created struct {struct_name}")

        ret_type, base, args = self.parse_current_func_type(ea)
        if ret_type is None or base is None or args is None:
            return False

        ret_type = struct_name

        self.update_current_func_type(ea, ret_type, base, args)
        return True


class SwiftIDAUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        global action_names
        if ida_kernwin.get_widget_type(form) not in [
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_PSEUDOCODE,
        ]:
            return
        for name in action_names:
            ida_kernwin.attach_action_to_popup(form, popup, name, "SwiftIDA/")


def generic_handler(callback):
    class Handler(ida_kernwin.action_handler_t):
        def __init__(self):
            ida_kernwin.action_handler_t.__init__(self)

        def activate(self, ctx):
            try:
                if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                    vu = ida_hexrays.get_widget_vdui(ctx.widget)
                    if vu.item.citype == ida_hexrays.VDI_FUNC:
                        ea = vu.item.f.entry_ea
                    else:
                        ea = vu.item.e.obj_ea
                else:
                    # TODO: Support call operand in disassembly view
                    ea = ida_kernwin.get_screen_ea()

                result = callback(ea)

                if result:
                    if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                        vu = ida_hexrays.get_widget_vdui(ctx.widget)
                        vu.refresh_view(True)
            except Exception as e:
                ida_kernwin.warning("There was an error, check logs")
                raise e
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    return Handler()


def PLUGIN_ENTRY():
    return SwiftIDA()
