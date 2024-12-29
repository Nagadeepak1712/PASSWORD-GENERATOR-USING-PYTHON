import tkinter as tk
from tkinter import messagebox
import random
import string

def generate_password():
    """Generate a password based on user-selected criteria."""
    try:
        length = int(length_entry.get())
        if length < 4:
            messagebox.showerror("Error", "Password length must be at least 4!")
            return

        include_uppercase = uppercase_var.get()
        include_numbers = numbers_var.get()
        include_symbols = symbols_var.get()

        # Character pools
        lower_chars = string.ascii_lowercase
        upper_chars = string.ascii_uppercase if include_uppercase else ""
        number_chars = string.digits if include_numbers else ""
        symbol_chars = string.punctuation if include_symbols else ""

        # Combine character pools
        all_chars = lower_chars + upper_chars + number_chars + symbol_chars
        if not all_chars:
            messagebox.showerror("Error", "Select at least one character type!")
            return

        # Ensure at least one of each selected type
        password = []
        if include_uppercase:
            password.append(random.choice(upper_chars))
        if include_numbers:
            password.append(random.choice(number_chars))
        if include_symbols:
            password.append(random.choice(symbol_chars))

        # Fill the rest of the password length
        while len(password) < length:
            password.append(random.choice(all_chars))

        # Shuffle to ensure randomness
        random.shuffle(password)
        result.set("".join(password))
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for length!")

def copy_to_clipboard():
    """Copy the generated password to clipboard."""
    password = result.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showerror("Error", "No password to copy!")

# Create the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("400x500")
root.configure(bg="#282c34")

# UI Variables
result = tk.StringVar()
uppercase_var = tk.BooleanVar()
numbers_var = tk.BooleanVar()
symbols_var = tk.BooleanVar()

# UI Components
title_label = tk.Label(root, text="Password Generator", font=("Helvetica", 18, "bold"), bg="#282c34", fg="#61dafb")
title_label.pack(pady=20)

length_frame = tk.Frame(root, bg="#282c34")
length_frame.pack(pady=10)
length_label = tk.Label(length_frame, text="Password Length:", font=("Helvetica", 12), bg="#282c34", fg="white")
length_label.pack(side=tk.LEFT, padx=5)
length_entry = tk.Entry(length_frame, width=10, font=("Helvetica", 12))
length_entry.pack(side=tk.LEFT, padx=5)

options_frame = tk.Frame(root, bg="#282c34")
options_frame.pack(pady=10)
uppercase_check = tk.Checkbutton(options_frame, text="Include Uppercase", font=("Helvetica", 12), variable=uppercase_var, bg="#282c34", fg="white", selectcolor="#282c34")
uppercase_check.pack(anchor=tk.W, pady=5)
numbers_check = tk.Checkbutton(options_frame, text="Include Numbers", font=("Helvetica", 12), variable=numbers_var, bg="#282c34", fg="white", selectcolor="#282c34")
numbers_check.pack(anchor=tk.W, pady=5)
symbols_check = tk.Checkbutton(options_frame, text="Include Symbols", font=("Helvetica", 12), variable=symbols_var, bg="#282c34", fg="white", selectcolor="#282c34")
symbols_check.pack(anchor=tk.W, pady=5)

result_label = tk.Label(root, text="Generated Password:", font=("Helvetica", 12), bg="#282c34", fg="white")
result_label.pack(pady=10)
result_entry = tk.Entry(root, textvariable=result, font=("Helvetica", 14), width=30, state="readonly", justify="center")
result_entry.pack(pady=5)

button_frame = tk.Frame(root, bg="#282c34")
button_frame.pack(pady=20)
generate_button = tk.Button(button_frame, text="Generate", font=("Helvetica", 12), command=generate_password, bg="#61dafb", fg="white", width=10)
generate_button.grid(row=0, column=0, padx=10)
copy_button = tk.Button(button_frame, text="Copy", font=("Helvetica", 12), command=copy_to_clipboard, bg="#61dafb", fg="white", width=10)
copy_button.grid(row=0, column=1, padx=10)

footer_label = tk.Label(root, text="Secure your passwords with ease!", font=("Helvetica", 10), bg="#282c34", fg="#61dafb")
footer_label.pack(side=tk.BOTTOM, pady=10)

# Run the application
root.mainloop()
