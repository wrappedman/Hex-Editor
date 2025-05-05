import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import customtkinter as ctk
import os
import threading
import string
import re

BYTES_PER_LINE = 16

class EXEHexEditor:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("EXE Hex Editor")
        self.window.geometry("1000x650")
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure(1, weight=1)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Top frame (modern, centered)
        self.top_frame = ctk.CTkFrame(self.window, corner_radius=15)
        self.top_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        self.top_frame.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)

        self.select_button = ctk.CTkButton(self.top_frame, text="Select EXE File", width=140, corner_radius=10)
        self.select_button.grid(row=0, column=0, padx=10, pady=10)

        self.file_label = ctk.CTkLabel(self.top_frame, text="No file selected", anchor="w")
        self.file_label.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.about_button = ctk.CTkButton(self.top_frame, text="About", width=80, corner_radius=10)
        self.about_button.grid(row=0, column=2, padx=10, pady=10)

        self.search_entry = ctk.CTkEntry(self.top_frame, width=220, placeholder_text="Search (hex or text)...")
        self.search_entry.grid(row=0, column=3, padx=10, pady=10)
        self.search_button = ctk.CTkButton(self.top_frame, text="Search", width=100, corner_radius=10)
        self.search_button.grid(row=0, column=4, padx=10, pady=10)

        self.show_strings_button = ctk.CTkButton(self.top_frame, text="Show Strings", width=120, corner_radius=10, command=self.show_strings_window)
        self.show_strings_button.grid(row=0, column=6, padx=10, pady=10)

        # Main frame (hex view)
        self.main_frame = ctk.CTkFrame(self.window, corner_radius=15)
        self.main_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        self.hex_text = tk.Text(self.main_frame, font=("Consolas", 12), wrap=tk.NONE, undo=True, bg="#23272f", fg="#f8f8f2", insertbackground="#00bfff", relief=tk.FLAT, borderwidth=0, highlightthickness=0)
        self.hex_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.hex_text.bind('<ButtonRelease-1>', self.on_cursor_move)
        self.hex_text.bind('<KeyRelease>', self.on_cursor_move)
        self.hex_text.bind('<Control-c>', self.copy_selected_event)
        self.hex_text.config(state=tk.DISABLED)
        self.scrollbar = ctk.CTkScrollbar(self.main_frame, command=self.hex_text.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns", pady=10)
        self.hex_text.config(yscrollcommand=self.scrollbar.set)

        # Bottom bar (card style)
        self.bottom_frame = ctk.CTkFrame(self.window, corner_radius=15)
        self.bottom_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="ew")
        self.bottom_frame.grid_columnconfigure((0,1,2,3), weight=1)

        self.ascii_label = ctk.CTkLabel(self.bottom_frame, text="ASCII:", anchor="e")
        self.ascii_label.grid(row=0, column=0, padx=10, pady=15, sticky="e")
        self.ascii_entry = ctk.CTkEntry(self.bottom_frame, width=300, font=("Consolas", 12))
        self.ascii_entry.grid(row=0, column=1, padx=10, pady=15, sticky="w")
        self.replace_button = ctk.CTkButton(self.bottom_frame, text="Replace (Dialog)", width=160, corner_radius=10, command=self.replace_dialog)
        self.replace_button.grid(row=0, column=2, padx=10, pady=15)
        self.copy_button = ctk.CTkButton(self.bottom_frame, text="Copy", width=100, corner_radius=10, command=self.copy_selected)
        self.copy_button.grid(row=0, column=3, padx=10, pady=15)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(self.window, variable=self.progress_var, width=400)
        self.progress_bar.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()

        self.current_file = None
        self.data = b''
        self.search_results = []
        self.current_search_index = -1

        self.select_button.configure(command=self.select_file)
        self.about_button.configure(command=self.show_about)
        self.search_button.configure(command=self.search_text)
        self.search_entry.bind('<Return>', lambda e: self.search_text())

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if file_path:
            self.current_file = file_path
            self.file_label.configure(text=os.path.basename(file_path))
            threading.Thread(target=self.load_file, daemon=True).start()

    def load_file(self):
        try:
            self.hex_text.config(state=tk.NORMAL)
            self.hex_text.delete('1.0', tk.END)
            self.progress_bar.set(0)
            self.progress_bar.grid()
            with open(self.current_file, 'rb') as f:
                self.data = f.read()
            lines = []
            total = len(self.data)
            for i in range(0, total, BYTES_PER_LINE):
                chunk = self.data[i:i+BYTES_PER_LINE]
                hex_part = ' '.join(f'{b:02X}' for b in chunk)
                # Standard ASCII: printable or dot
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                try:
                    utf8_part = chunk.decode('utf-8')
                except Exception:
                    utf8_part = '.' * len(chunk)
                lines.append(f'{i:08X}  {hex_part:<48}  {ascii_part:<16}  {utf8_part}')
                if i % (BYTES_PER_LINE*128) == 0 or i+BYTES_PER_LINE >= total:
                    self.progress_var.set((i+BYTES_PER_LINE)/total)
                    self.window.update_idletasks()
            # Add header
            header = f'Offset    {"Hex":<48}  {"ASCII":<16}  UTF-8'
            self.hex_text.insert(tk.END, header + '\n' + '\n'.join(lines))
            self.hex_text.config(state=tk.DISABLED)
            self.progress_bar.grid_remove()
        except Exception as e:
            self.progress_bar.grid_remove()
            messagebox.showerror("Error", f"Error loading file: {str(e)}")

    def on_cursor_move(self, event=None):
        try:
            sel = self.hex_text.tag_ranges(tk.SEL)
            if sel:
                start_idx = self.hex_text.index(sel[0])
                end_idx = self.hex_text.index(sel[1])
                start_line = int(start_idx.split('.')[0]) - 2
                start_col = int(start_idx.split('.')[1])
                end_line = int(end_idx.split('.')[0]) - 2
                end_col = int(end_idx.split('.')[1])
                start_offset = start_line * BYTES_PER_LINE
                end_offset = end_line * BYTES_PER_LINE
                if start_col >= 10 and start_col < 59:
                    start_offset += (start_col - 10) // 3
                elif start_col >= 60 and start_col < 77:
                    start_offset += start_col - 60
                if end_col >= 10 and end_col < 59:
                    end_offset += (end_col - 10) // 3
                elif end_col >= 60 and end_col < 77:
                    end_offset += end_col - 60
                if end_offset < start_offset:
                    start_offset, end_offset = end_offset, start_offset
                if end_offset >= len(self.data):
                    end_offset = len(self.data) - 1
                selected_bytes = self.data[start_offset:end_offset+1]
                ascii_val = ''.join(chr(b) if 32 <= b < 127 else '.' for b in selected_bytes)
                self.ascii_entry.delete(0, tk.END)
                self.ascii_entry.insert(0, ascii_val)
                self.show_ascii_replace_dialog(start_offset, end_offset, ascii_val)
                return
        except Exception:
            pass
        # fallback to single-byte
        try:
            index = self.hex_text.index(tk.INSERT)
            line = int(index.split('.')[0]) - 2
            col = int(index.split('.')[1])
            offset = line * BYTES_PER_LINE
            if line < 0 or offset >= len(self.data):
                return
            if col >= 10 and col < 59:
                hex_col = (col - 10) // 3
                offset += hex_col
            elif col >= 60 and col < 77:
                ascii_col = col - 60
                offset += ascii_col
            b = self.data[offset]
            self.ascii_entry.delete(0, tk.END)
            self.ascii_entry.insert(0, chr(b) if 32 <= b < 127 else '.')
        except Exception:
            pass

    def replace_dialog(self):
        # fallback for manual button (select something first)
        sel = self.hex_text.tag_ranges(tk.SEL)
        if sel:
            start_idx = self.hex_text.index(sel[0])
            end_idx = self.hex_text.index(sel[1])
            start_line = int(start_idx.split('.')[0]) - 1
            start_col = int(start_idx.split('.')[1])
            end_line = int(end_idx.split('.')[0]) - 1
            end_col = int(end_idx.split('.')[1])
            start_offset = start_line * BYTES_PER_LINE
            end_offset = end_line * BYTES_PER_LINE
            if start_col >= 10 and start_col < 59:
                start_offset += (start_col - 10) // 3
            elif start_col >= 60:
                start_offset += start_col - 60
            if end_col >= 10 and end_col < 59:
                end_offset += (end_col - 10) // 3
            elif end_col >= 60:
                end_offset += end_col - 60
            if end_offset < start_offset:
                start_offset, end_offset = end_offset, start_offset
            if end_offset >= len(self.data):
                end_offset = len(self.data) - 1
            selected_bytes = self.data[start_offset:end_offset+1]
            self.show_replace_dialog(start_offset, end_offset, selected_bytes)

    def show_replace_dialog(self, start_offset, end_offset, selected_bytes):
        current_val = selected_bytes.decode('utf-8', errors='replace')
        new_val = simpledialog.askstring("Replace", f"Current value:\n{current_val}\n\nEnter new ASCII value (max {len(selected_bytes)} chars):", parent=self.window)
        if new_val is None:
            return
        if any(ord(c) > 127 for c in new_val):
            messagebox.showerror("Error", "Only ASCII characters are allowed.")
            return
        if len(new_val) > len(selected_bytes):
            messagebox.showerror("Error", "Replacement is longer than selection.")
            return
        new_bytes = new_val.encode('ascii')
        if len(new_bytes) < len(selected_bytes):
            new_bytes = new_bytes + b' ' * (len(selected_bytes) - len(new_bytes))
        try:
            backup_file = self.current_file + '.backup'
            with open(backup_file, 'wb') as f:
                f.write(self.data)
            new_data = bytearray(self.data)
            new_data[start_offset:end_offset+1] = new_bytes
            with open(self.current_file, 'wb') as f:
                f.write(new_data)
            self.data = bytes(new_data)
            messagebox.showinfo("Success", "Selection replaced successfully. A backup file has been created.")
            threading.Thread(target=self.load_file, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Error replacing selection: {str(e)}")

    def show_full_string_dialog(self, start_offset, end_offset, selected_bytes):
        current_val = selected_bytes.decode('ascii', errors='replace')
        new_val = simpledialog.askstring("Replace String", f"Current string:\n{current_val}\n\nEnter new ASCII value (max {len(selected_bytes)} chars):", parent=self.window)
        if new_val is None:
            return
        if any(ord(c) > 127 for c in new_val):
            messagebox.showerror("Error", "Only ASCII characters are allowed.")
            return
        if len(new_val) > len(selected_bytes):
            messagebox.showerror("Error", "Replacement is longer than string.")
            return
        new_bytes = new_val.encode('ascii')
        if len(new_bytes) < len(selected_bytes):
            new_bytes = new_bytes + b' ' * (len(selected_bytes) - len(new_bytes))
        try:
            backup_file = self.current_file + '.backup'
            with open(backup_file, 'wb') as f:
                f.write(self.data)
            new_data = bytearray(self.data)
            new_data[start_offset:end_offset+1] = new_bytes
            with open(self.current_file, 'wb') as f:
                f.write(new_data)
            self.data = bytes(new_data)
            messagebox.showinfo("Success", "String replaced successfully. A backup file has been created.")
            threading.Thread(target=self.load_file, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Error replacing string: {str(e)}")

    def search_text(self, next_result=False):
        term = self.search_entry.get()
        if not term:
            return
        # Try hex search first
        start_pos = getattr(self, 'last_search_pos', 0)
        try:
            if all(c in string.hexdigits+' ' for c in term):
                hex_bytes = bytes.fromhex(term)
                idx = self.data.find(hex_bytes, start_pos)
                if idx != -1:
                    self.goto_offset(idx)
                    self.last_search_pos = idx + 1
                    return
        except Exception:
            pass
        # Text search
        idx = self.data.find(term.encode('utf-8'), start_pos)
        if idx != -1:
            self.goto_offset(idx)
            self.last_search_pos = idx + 1
        else:
            messagebox.showinfo("Search", f'"{term}" not found or end of file reached.')
            self.last_search_pos = 0

    def goto_offset(self, offset):
        # When searching, also show full string dialog
        self.on_cursor_move()
        line = offset // BYTES_PER_LINE
        col = 10 + (offset % BYTES_PER_LINE) * 3
        self.hex_text.see(f'{line+2}.0')
        self.hex_text.tag_remove('search_highlight', '1.0', tk.END)
        self.hex_text.tag_add('search_highlight', f'{line+2}.{col}', f'{line+2}.{col+2}')
        self.hex_text.tag_config('search_highlight', background='yellow', foreground='black')
        self.hex_text.mark_set(tk.INSERT, f'{line+2}.{col}')
        self.on_cursor_move()

    def copy_selected(self):
        try:
            sel = self.hex_text.selection_get()
            self.window.clipboard_clear()
            self.window.clipboard_append(sel)
            self.window.update()
        except Exception:
            pass

    def copy_selected_event(self, event):
        self.copy_selected()
        return "break"

    def show_about(self):
        messagebox.showinfo("About", "created by behnam ehsani")

    def show_strings_window(self):
        win = ctk.CTkToplevel(self.window)
        win.title("Strings in File")
        win.geometry("600x500")
        # Search bar
        search_var = tk.StringVar()
        search_entry = ctk.CTkEntry(win, width=300, placeholder_text="Search strings...", textvariable=search_var)
        search_entry.pack(padx=10, pady=(10, 0), fill=tk.X)
        search_button = ctk.CTkButton(win, text="Search", width=80)
        search_button.pack(padx=10, pady=(0, 10), anchor="e")
        listbox = tk.Listbox(win, font=("Consolas", 12))
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Find all ASCII/UTF-8 strings (min 3 chars)
        ascii_pattern = re.compile(b'([\x20-\x7E]{3,})')
        utf8_pattern = re.compile(b'((?:[\x09\x0A\x0D\x20-\x7E]|[\xC2-\xF4][\x80-\xBF]+){3,})')
        found = set()
        all_strings = []
        for match in ascii_pattern.finditer(self.data):
            s = match.group(0).decode('ascii', errors='replace')
            if s not in found:
                found.add(s)
                all_strings.append(s)
        for match in utf8_pattern.finditer(self.data):
            try:
                s = match.group(0).decode('utf-8')
                if s not in found:
                    found.add(s)
                    all_strings.append(s)
            except Exception:
                continue
        def update_list(filter_text=None):
            listbox.delete(0, tk.END)
            for s in all_strings:
                if not filter_text or filter_text.lower() in s.lower():
                    listbox.insert(tk.END, s)
        update_list()
        def do_search(*_):
            filter_text = search_var.get()
            update_list(filter_text)
        search_button.configure(command=do_search)
        search_entry.bind('<Return>', do_search)
        def on_select(evt):
            idx = listbox.curselection()
            if idx:
                val = listbox.get(idx[0])
                offset = self.data.find(val.encode('utf-8'))
                if offset == -1:
                    offset = self.data.find(val.encode('ascii', errors='replace'))
                if offset != -1:
                    self.goto_offset(offset)
                    win.destroy()
        listbox.bind('<<ListboxSelect>>', on_select)

    def show_ascii_replace_dialog(self, start_offset, end_offset, ascii_val):
        new_val = simpledialog.askstring("Replace", f"Current ASCII value:\n{ascii_val}\n\nEnter new ASCII value (max {end_offset-start_offset+1} chars):", parent=self.window)
        if new_val is None:
            return
        if any(ord(c) > 127 for c in new_val):
            messagebox.showerror("Error", "Only ASCII characters are allowed.")
            return
        if len(new_val) > (end_offset-start_offset+1):
            messagebox.showerror("Error", "Replacement is longer than selection.")
            return
        new_bytes = new_val.encode('ascii')
        if len(new_bytes) < (end_offset-start_offset+1):
            new_bytes = new_bytes + b' ' * ((end_offset-start_offset+1) - len(new_bytes))
        try:
            backup_file = self.current_file + '.backup'
            with open(backup_file, 'wb') as f:
                f.write(self.data)
            new_data = bytearray(self.data)
            new_data[start_offset:end_offset+1] = new_bytes
            with open(self.current_file, 'wb') as f:
                f.write(new_data)
            self.data = bytes(new_data)
            messagebox.showinfo("Success", "Selection replaced successfully. A backup file has been created.")
            threading.Thread(target=self.load_file, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Error replacing selection: {str(e)}")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = EXEHexEditor()
    app.run() 