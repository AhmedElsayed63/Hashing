import tkinter as tk
from tkinter import scrolledtext, messagebox
import hashlib, binascii

def crc32_hash(data):
    return format(binascii.crc32(data.encode('utf-8')) & 0xffffffff, '08X')

def md5_hash(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def generate_hash():
    text = input_box.get("1.0", tk.END).strip()
    algo = algo_var.get()
    if not text:
        messagebox.showinfo("Info", "اكتب نص علشان نحسب الهاش")
        return
    if algo == "CRC32":
        result = crc32_hash(text)
    elif algo == "MD5":
        result = md5_hash(text)
    else:
        result = "Unsupported"
    output_box.config(state='normal')
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, result)
    output_box.config(state='disabled')

# واجهة البرنامج
root = tk.Tk()
root.title("Hash Generator (CRC32 & MD5)")
root.geometry("600x400")
root.configure(bg="#171717")

tk.Label(root, text="Data Integrity & Hash Generator", fg="#00d35a", bg="#171717", font=("Segoe UI", 16, "bold")).pack(pady=10)

tk.Label(root, text="ادخل النص:", fg="white", bg="#171717", font=("Segoe UI", 10)).pack(anchor='w', padx=20)
input_box = scrolledtext.ScrolledText(root, height=6, width=70, bg="#2d2d2d", fg="white")
input_box.pack(padx=20, pady=5)

tk.Label(root, text="اختار الخوارزمية:", fg="white", bg="#171717", font=("Segoe UI", 10)).pack(anchor='w', padx=20, pady=(10,0))
algo_var = tk.StringVar(value="CRC32")
algo_menu = tk.OptionMenu(root, algo_var, "CRC32", "MD5")
algo_menu.pack(padx=20, anchor='w')

tk.Button(root, text="احسب الهاش", command=generate_hash, bg="#00d35a", fg="#012", font=("Segoe UI", 10, "bold")).pack(pady=15)

tk.Label(root, text="النتيجة:", fg="white", bg="#171717").pack(anchor='w', padx=20)
output_box = scrolledtext.ScrolledText(root, height=4, width=70, bg="#2d2d2d", fg="#00d35a", state='disabled')
output_box.pack(padx=20, pady=5)

root.mainloop()
