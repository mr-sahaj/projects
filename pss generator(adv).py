import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Password Generator")

        self.length_label = tk.Label(self, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.length_entry = tk.Entry(self)
        self.length_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.complexity_label = tk.Label(self, text="Password Complexity:")
        self.complexity_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.complexity_var = tk.StringVar()
        self.complexity_var.set("Medium")
        self.complexity_menu = tk.OptionMenu(self, self.complexity_var, "Low", "Medium", "High")
        self.complexity_menu.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.generate_button = tk.Button(self, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.password_label = tk.Label(self, text="Generated Password:")
        self.password_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = tk.Entry(self, state="readonly")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        self.copy_button = tk.Button(self, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            if length <= 0:
                raise ValueError("Length must be a positive integer")

            complexity = self.complexity_var.get()
            password = self.generate_random_password(length, complexity)
            self.password_entry.config(state="normal")
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)
            self.password_entry.config(state="readonly")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def generate_random_password(self, length, complexity):
        complexity_rules = {
            "Low": string.ascii_letters + string.digits,
            "Medium": string.ascii_letters + string.digits + string.punctuation,
            "High": string.ascii_letters + string.digits + string.punctuation + "£$€"
        }

        return ''.join(random.choice(complexity_rules[complexity]) for _ in range(length))

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

if __name__ == "__main__":
    app = PasswordGenerator()
    app.mainloop()

