import tkinter as tk
from tkinter import scrolledtext
import requests
import socketio
from tkinter import filedialog
import os

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Client")
        
        self.sio = socketio.Client()
        self.sio.on('new_message', self.on_new_message)

        self.chat_display = scrolledtext.ScrolledText(master, state='disabled')
        self.chat_display.pack(padx=10, pady=10)

        self.msg_entry = tk.Entry(master)
        self.msg_entry.pack(padx=10, pady=10, side=tk.LEFT)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(pady=10, side=tk.LEFT)

        self.login_button = tk.Button(master, text="Login", command=self.show_login_dialog)
        self.login_button.pack(pady=10, side=tk.RIGHT)

        self.user_id = None
        self.token = None

    def show_login_dialog(self):
        login_window = tk.Toplevel(self.master)
        login_window.title("Login")

        tk.Label(login_window, text="Username:").grid(row=0, column=0)
        username_entry = tk.Entry(login_window)
        username_entry.grid(row=0, column=1)

        tk.Label(login_window, text="Password:").grid(row=1, column=0)
        password_entry = tk.Entry(login_window, show="*")
        password_entry.grid(row=1, column=1)

        login_button = tk.Button(login_window, text="Login", 
                                 command=lambda: self.login(username_entry.get(), password_entry.get()))
        login_button.grid(row=2, column=0, columnspan=2)

    def login(self, username, password):
        response = requests.post('http://localhost:5000/login', 
                                 auth=(username, password))
        if response.status_code == 200:
            data = response.json()
            self.token = data['token']
            self.user_id = data['user_id']
            self.sio.connect('http://localhost:5000')
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, "Logged in successfully\n")
            self.chat_display.config(state='disabled')
        else:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, "Login failed\n")
            self.chat_display.config(state='disabled')

    def send_message(self):
        if not self.user_id:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, "Please login first\n")
            self.chat_display.config(state='disabled')
            return

        message = self.msg_entry.get()
        self.sio.emit('send_message', {'message': message, 'user_id': self.user_id})
        self.msg_entry.delete(0, tk.END)

    def on_new_message(self, data):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{data['sender']}: {data['message']}\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()