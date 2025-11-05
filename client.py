#!/usr/bin/env python3
"""
client.py
- Tkinter chat client
- register with username
- send chat, pm (/pm or /w), and file (send small files)
- periodic Cristian sync (short-lived socket)
- displays Local Time and Synced Server Time
"""

import socket
import threading
import json
import time
import tkinter as tk
import tkinter.scrolledtext as scrolledtext
from queue import Queue
import base64
from tkinter import filedialog, messagebox

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
SYNC_INTERVAL = 5.0       # seconds between syncs
SIMULATE_DRIFT = True     # toggle client-side drift simulation
DRIFT_PER_SEC = 0.0008    # how many seconds local clock drifts per real second
MAX_FILE_BYTES = 6 * 1024 * 1024  # 6 MB limit for demo

class ChatClient:
    def __init__(self, host, port, username):
        self.host = host
        self.port = port
        self.username = username

        self.sock = None
        self.running = False
        self.recv_thread = None

        self.ui_q = Queue()

        # Cristian offset: server_time - local_time
        self.server_offset = 0.0

        # simulated local clock offset (drift)
        self.sim_local_offset = 0.0
        self.last_drift_update = time.time()

        self.build_gui()
        self.connect()
        # send register
        self.send_json({"type":"register", "username": self.username})

        # start periodic sync thread (uses dedicated short-lived socket)
        t = threading.Thread(target=self.sync_loop, daemon=True)
        t.start()

        # start UI polling and clock update
        self.root.after(150, self.ui_poll)
        self.root.after(200, self.update_clock_labels)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title(f"Chat - {self.username}")
        self.frame = tk.Frame(self.root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.chat = scrolledtext.ScrolledText(self.frame, state="disabled", height=20, wrap=tk.WORD)
        self.chat.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        entry_frame = tk.Frame(self.frame)
        entry_frame.pack(fill=tk.X, padx=6, pady=(0,6))
        self.entry = tk.Entry(entry_frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", lambda e: self.on_send())

        send_btn = tk.Button(entry_frame, text="Send", command=self.on_send)
        send_btn.pack(side=tk.LEFT, padx=4)
        file_btn = tk.Button(entry_frame, text="Send File", command=self.on_send_file)
        file_btn.pack(side=tk.LEFT, padx=4)

        times_frame = tk.Frame(self.root)
        times_frame.pack(fill=tk.X, padx=6, pady=(0,6))
        self.local_lbl = tk.Label(times_frame, text="Local Time: -")
        self.local_lbl.pack(side=tk.LEFT, padx=4)
        self.synced_lbl = tk.Label(times_frame, text="Synced Server Time: -")
        self.synced_lbl.pack(side=tk.LEFT, padx=20)
        self.offset_lbl = tk.Label(times_frame, text="Offset: 0.000s")
        self.offset_lbl.pack(side=tk.RIGHT, padx=6)

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.running = True
        self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)
        self.recv_thread.start()
        self.append_chat("[*] Connected to server\n")

    def recv_loop(self):
        f = self.sock.makefile(mode="r", encoding="utf-8")
        try:
            while self.running:
                line = f.readline()
                if not line:
                    break
                try:
                    obj = json.loads(line.strip())
                    self.ui_q.put(obj)
                except Exception as e:
                    print("Bad incoming:", e)
        except Exception as e:
            print("Recv loop error:", e)
        self.running = False
        self.ui_q.put({"type":"system", "text":"Disconnected from server"})

    def ui_poll(self):
        while not self.ui_q.empty():
            obj = self.ui_q.get()
            self.handle_msg(obj)
        self.root.after(150, self.ui_poll)

    def format_time(self, t):
        if t is None:
            return "-"
        return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t%1)*1000):03d}"

    def handle_msg(self, obj):
        typ = obj.get("type")
        if typ == "chat":
            user = obj.get("username", "unknown")
            text = obj.get("text","")
            client_ts = obj.get("client_time")
            server_recv = obj.get("server_recv_time")
            meta = []
            if client_ts: meta.append("c@" + self.format_time(client_ts))
            if server_recv: meta.append("srv@" + self.format_time(server_recv))
            meta_s = " ".join(meta)
            self.append_chat(f"[{user}] {text} ({meta_s})\n")
        elif typ == "pm":
            frm = obj.get("from") or obj.get("username")
            text = obj.get("text","")
            self.append_chat(f"[PM from {frm}] {text}\n")
        elif typ == "file":
            # file message: {'type':'file','username':..., 'filename':..., 'b64':..., 'filesize':...}
            sender = obj.get("username")
            fname = obj.get("filename")
            size = obj.get("filesize",0)
            self.append_chat(f"[FILE] {sender} sent {fname} ({size} bytes). Click to save.\n")
            # provide local save prompt immediately
            if messagebox.askyesno("File received", f"{sender} sent {fname} ({size} bytes).\nSave file?"):
                try:
                    b64 = obj.get("b64")
                    data = base64.b64decode(b64)
                    savep = filedialog.asksaveasfilename(initialfile=fname)
                    if savep:
                        with open(savep, "wb") as fh:
                            fh.write(data)
                        self.append_chat(f"[SAVED] {savep}\n")
                except Exception as e:
                    messagebox.showerror("Save error", str(e))
        elif typ == "sync_response":
            # Sync responses are shown by sync thread; ignore here or show arrival
            srv = obj.get("server_time")
            self.append_chat(f"[*] Sync response: server_time={self.format_time(srv)}\n")
        elif typ == "system":
            self.append_chat(f"[*] {obj.get('text')}\n")
        else:
            self.append_chat(f"[?] Unknown incoming: {typ}\n")

    def append_chat(self, text):
        self.chat.configure(state="normal")
        self.chat.insert(tk.END, text)
        self.chat.see(tk.END)
        self.chat.configure(state="disabled")

    def on_send(self):
        text = self.entry.get().strip()
        if not text:
            return
        # check for private message commands
        if text.startswith("/pm ") or text.startswith("/w "):
            parts = text.split(" ", 2)
            if len(parts) < 3:
                self.append_chat("[!] PM usage: /pm username message\n")
            else:
                _, target, msg = parts
                payload = {"type":"pm", "from": self.username, "to": target, "text": msg, "client_time": self.get_sim_time()}
                self.send_json(payload)
                self.append_chat(f"[PM to {target}] {msg}\n")
        else:
            payload = {"type":"chat", "username": self.username, "text": text, "client_time": self.get_sim_time()}
            self.send_json(payload)
        self.entry.delete(0, tk.END)

    def on_send_file(self):
        # choose file
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            if len(data) > MAX_FILE_BYTES:
                messagebox.showerror("File too large", f"Max file size is {MAX_FILE_BYTES} bytes.")
                return
            b64 = base64.b64encode(data).decode("ascii")
            fname = path.split("/")[-1]
            payload = {"type":"file", "username": self.username, "filename": fname, "filesize": len(data), "b64": b64}
            self.send_json(payload)
            self.append_chat(f"[You] sent file {fname} ({len(data)} bytes)\n")
        except Exception as e:
            messagebox.showerror("File error", str(e))

    def send_json(self, obj):
        try:
            self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        except Exception as e:
            self.append_chat(f"[!] Send failed: {e}\n")

    def sync_loop(self):
        # Cristian sync using a short-lived socket (so main recv thread isn't blocked)
        while True:
            try:
                self.update_drift()
                t0 = self.get_wall_time()
                req = {"type":"sync_request"}
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                    s2.settimeout(2.0)
                    s2.connect((self.host, self.port))
                    s2.sendall((json.dumps(req) + "\n").encode("utf-8"))
                    f2 = s2.makefile(mode="r", encoding="utf-8")
                    line = f2.readline()
                    t2 = self.get_wall_time()
                    if not line:
                        raise Exception("no reply")
                    obj = json.loads(line.strip())
                    if obj.get("type") == "sync_response":
                        server_t = obj.get("server_time")
                        rtt = t2 - t0
                        offset = (server_t + rtt/2.0) - t2
                        self.server_offset = offset
                        self.ui_q.put({"type":"system", "text": f"Sync done offset={offset:.4f}s rtt={rtt:.4f}s"})
            except Exception as e:
                self.ui_q.put({"type":"system", "text": f"Sync error: {e}"})
            time.sleep(SYNC_INTERVAL)

    def get_wall_time(self):
        # includes simulated drift
        self.update_drift()
        return time.time() + self.sim_local_offset

    def get_sim_time(self):
        self.update_drift()
        return time.time() + self.sim_local_offset

    def update_drift(self):
        if not SIMULATE_DRIFT:
            return
        now = time.time()
        elapsed = now - self.last_drift_update
        if elapsed > 0:
            self.sim_local_offset += DRIFT_PER_SEC * elapsed
            self.last_drift_update = now

    def update_clock_labels(self):
        local = self.get_sim_time()
        synced = local + self.server_offset
        self.local_lbl.config(text=f"Local Time: {self.format_time(local)}")
        self.synced_lbl.config(text=f"Synced Server Time: {self.format_time(synced)}")
        self.offset_lbl.config(text=f"Offset: {self.server_offset:.4f}s")
        self.root.after(200, self.update_clock_labels)

    def on_close(self):
        try:
            self.running = False
            if self.sock:
                self.sock.close()
        except:
            pass
        self.root.destroy()

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=SERVER_HOST)
    parser.add_argument("--port", default=SERVER_PORT, type=int)
    parser.add_argument("--name", default=None)
    args = parser.parse_args()
    name = args.name or input("Username: ").strip() or "user"
    ChatClient(args.host, args.port, name)

if __name__ == "__main__":
    main()



