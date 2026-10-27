#!/usr/bin/env python3
"""
PHP Web Application CVE Scanner — Graphical User Interface
==========================================================
A modern dark-themed GUI wrapper for php_app_cve_scanner.py.
Uses only the standard library (tkinter). No pip dependencies.
"""

import importlib.util
import io
import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

# ---------------------------------------------------------------------------
# Colour / theme tokens
# ---------------------------------------------------------------------------
BG       = "#0d1117"   # near-black
BG2      = "#161b22"   # card background
BG3      = "#21262d"   # input background
BORDER   = "#30363d"   # border / separator
ACCENT   = "#58a6ff"   # blue accent
ACCENT2  = "#1f6feb"   # darker blue
GREEN    = "#3fb950"
YELLOW   = "#d29922"
RED      = "#f85149"
ORANGE   = "#e3b341"
PURPLE   = "#bc8cff"
TEXT     = "#e6edf3"
TEXT2    = "#8b949e"
TEXT3    = "#6e7681"

# Severity colours
SEV_COLOR = {
    "CRITICAL":       RED,
    "HIGH":           ORANGE,
    "MEDIUM":         YELLOW,
    "LOW":            TEXT2,
    "INFO":           ACCENT,
}
STATUS_COLOR = {
    "CONFIRMED":      RED,
    "LIKELY":         ORANGE,
    "POSSIBLE":       YELLOW,
    "NOT_VULNERABLE": GREEN,
    "NOT_APPLICABLE": TEXT3,
    "ERROR":          PURPLE,
}


# ---------------------------------------------------------------------------
# Load scanner module without executing __main__
# ---------------------------------------------------------------------------
def load_scanner_module():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scanner_path = os.path.join(script_dir, "php_app_cve_scanner.py")
    if not os.path.exists(scanner_path):
        return None
    spec = importlib.util.spec_from_file_location("php_app_cve_scanner", scanner_path)
    mod = importlib.util.module_from_spec(spec)
    # Must register in sys.modules BEFORE exec_module so dataclass
    # introspection (cls.__module__ lookup) works correctly.
    sys.modules["php_app_cve_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod


SCANNER = load_scanner_module()


# ---------------------------------------------------------------------------
# Styled widgets helpers
# ---------------------------------------------------------------------------
def styled_entry(parent, width=40, **kw):
    e = tk.Entry(
        parent,
        bg=BG3, fg=TEXT, insertbackground=ACCENT,
        relief="flat", bd=0, highlightthickness=1,
        highlightcolor=ACCENT, highlightbackground=BORDER,
        font=("Consolas", 10), width=width, **kw
    )
    return e


def styled_label(parent, text, fg=TEXT, size=10, bold=False, **kw):
    weight = "bold" if bold else "normal"
    return tk.Label(parent, text=text, bg=BG2, fg=fg,
                    font=("Segoe UI", size, weight), **kw)


def styled_check(parent, text, var, **kw):
    return tk.Checkbutton(
        parent, text=text, variable=var,
        bg=BG2, fg=TEXT2, selectcolor=BG3,
        activebackground=BG2, activeforeground=TEXT,
        font=("Segoe UI", 9), **kw
    )


# ---------------------------------------------------------------------------
# Tooltip helper
# ---------------------------------------------------------------------------
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 24
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            self.tip, text=self.text, bg="#1c2128", fg=TEXT,
            relief="flat", bd=1, font=("Segoe UI", 8),
            padx=6, pady=4, wraplength=300, justify="left"
        )
        lbl.pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
class PhpScannerGUI(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("PHP CVE Scanner 2.0")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(920, 680)

        # State
        self._scan_thread = None
        self._log_queue = queue.Queue()
        self._result_data = None
        self._running = False

        self._build_ui()
        self._poll_log_queue()
        self.after(100, self._center_window)

    def _center_window(self):
        self.update_idletasks()
        w, h = 1200, 780
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        # ---- Header bar ----
        header = tk.Frame(self, bg=BG2, height=54)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header, text="⬡  PHP CVE SCANNER", bg=BG2, fg=ACCENT,
            font=("Segoe UI", 15, "bold"), anchor="w", padx=18
        ).pack(side="left", fill="y")

        tk.Label(
            header, text="2026 php2shell · RCE surface detection",
            bg=BG2, fg=TEXT2, font=("Segoe UI", 9), anchor="e", padx=18
        ).pack(side="right", fill="y")

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # ---- Main layout: left config, right output ----
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Left panel (config)
        left = tk.Frame(body, bg=BG2, width=360)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        vsep = tk.Frame(body, bg=BORDER, width=1)
        vsep.pack(side="left", fill="y")

        # Right panel (output)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_config_panel(left)
        self._build_output_panel(right)

        # ---- Status bar ----
        statusbar = tk.Frame(self, bg=BG2, height=26)
        statusbar.pack(fill="x", side="bottom")
        statusbar.pack_propagate(False)

        self._status_var = tk.StringVar(value="Ready")
        tk.Label(
            statusbar, textvariable=self._status_var,
            bg=BG2, fg=TEXT2, font=("Segoe UI", 8), anchor="w", padx=12
        ).pack(side="left", fill="y")

        self._elapsed_var = tk.StringVar(value="")
        tk.Label(
            statusbar, textvariable=self._elapsed_var,
            bg=BG2, fg=TEXT3, font=("Consolas", 8), anchor="e", padx=12
        ).pack(side="right", fill="y")

    def _section(self, parent, title):
        """Returns a frame under a section heading."""
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=14, pady=(12, 0))
        tk.Label(
            parent, text=title.upper(), bg=BG2, fg=TEXT3,
            font=("Segoe UI", 7, "bold"), anchor="w", padx=14
        ).pack(fill="x")
        frame = tk.Frame(parent, bg=BG2)
        frame.pack(fill="x", padx=14, pady=(2, 4))
        return frame

    def _build_config_panel(self, parent):
        canvas = tk.Canvas(parent, bg=BG2, highlightthickness=0)
        scroll = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        canvas.configure(yscrollcommand=scroll.set)

        inner = tk.Frame(canvas, bg=BG2)
        inner_win = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_frame_config(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def on_canvas_config(e):
            canvas.itemconfig(inner_win, width=e.width)
        inner.bind("<Configure>", on_frame_config)
        canvas.bind("<Configure>", on_canvas_config)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        # ---- Target URL ----
        tk.Label(inner, text="PHP CVE Scanner", bg=BG2, fg=TEXT,
                 font=("Segoe UI", 13, "bold"), anchor="w", padx=14
                 ).pack(fill="x", pady=(18, 2))
        tk.Label(inner, text="Configure scan parameters below",
                 bg=BG2, fg=TEXT2, font=("Segoe UI", 8), anchor="w", padx=14
                 ).pack(fill="x", pady=(0, 6))

        sec = self._section(inner, "Target")
        tk.Label(sec, text="URL *", bg=BG2, fg=TEXT2, font=("Segoe UI", 8), anchor="w"
                 ).grid(row=0, column=0, sticky="w", pady=(4, 1))
        self._url_var = tk.StringVar()
        url_entry = styled_entry(sec, width=32)
        url_entry["textvariable"] = self._url_var
        url_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        sec.columnconfigure(0, weight=1)
        Tooltip(url_entry, "Root URL of the target app, e.g. https://app.example/")

        # ---- Crawl settings ----
        sec2 = self._section(inner, "Crawl Settings")
        for i, (lbl, var_name, default, tip) in enumerate([
            ("Depth",     "_depth_var",    "3",   "Max crawl depth (default 3)"),
            ("Max Pages", "_maxpages_var", "100", "Max pages to fetch (default 100)"),
            ("Timeout",   "_timeout_var",  "12",  "Per-request timeout in seconds"),
            ("Delay (s)", "_delay_var",    "0",   "Delay between requests (rate limiting)"),
        ]):
            tk.Label(sec2, text=lbl, bg=BG2, fg=TEXT2, font=("Segoe UI", 8), anchor="w"
                     ).grid(row=i*2, column=0, sticky="w", pady=(4, 0))
            var = tk.StringVar(value=default)
            setattr(self, var_name, var)
            e = styled_entry(sec2, width=14)
            e["textvariable"] = var
            e.grid(row=i*2+1, column=0, sticky="ew", pady=(0, 4))
            Tooltip(e, tip)
        sec2.columnconfigure(0, weight=1)

        # ---- Auth ----
        sec3 = self._section(inner, "Auth / Headers")
        tk.Label(sec3, text="Cookie", bg=BG2, fg=TEXT2, font=("Segoe UI", 8), anchor="w"
                 ).grid(row=0, column=0, sticky="w", pady=(4, 0))
        self._cookie_var = tk.StringVar()
        ce = styled_entry(sec3, width=32)
        ce["textvariable"] = self._cookie_var
        ce.grid(row=1, column=0, sticky="ew")
        Tooltip(ce, 'Cookie header value, e.g. "PHPSESSID=abc; session=xyz"')

        tk.Label(sec3, text="Extra Header (Name: value)", bg=BG2, fg=TEXT2,
                 font=("Segoe UI", 8), anchor="w").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self._header_var = tk.StringVar()
        he = styled_entry(sec3, width=32)
        he["textvariable"] = self._header_var
        he.grid(row=3, column=0, sticky="ew")
        Tooltip(he, 'Extra header, e.g. "Authorization: Bearer TOKEN"')

        tk.Label(sec3, text="User-Agent", bg=BG2, fg=TEXT2, font=("Segoe UI", 8), anchor="w"
                 ).grid(row=4, column=0, sticky="w", pady=(8, 0))
        self._ua_var = tk.StringVar(value="PHP-App-CVE-Scanner/2.0")
        uae = styled_entry(sec3, width=32)
        uae["textvariable"] = self._ua_var
        uae.grid(row=5, column=0, sticky="ew")
        sec3.columnconfigure(0, weight=1)

        # ---- Flags ----
        sec4 = self._section(inner, "Scan Flags")
        flags = [
            ("_only2026_var",    "Only 2026 CVEs",    "Only test CVE-2026-109618/109619/115560"),
            ("_aggressive_var",  "Aggressive probes", "Heavier multipart / OOM-adjacent probes"),
            ("_secure_var",      "Verify TLS",        "Verify TLS certificates (off by default)"),
            ("_subdomains_var",  "Follow subdomains",  "Follow links to sibling subdomains"),
            ("_robots_var",      "Respect robots.txt", "Honour robots.txt exclusions"),
            ("_quiet_var",       "Quiet mode",         "Less crawl chatter in the log"),
        ]
        for i, (vname, lbl, tip) in enumerate(flags):
            var = tk.BooleanVar(value=False)
            setattr(self, vname, var)
            cb = styled_check(sec4, lbl, var)
            cb.grid(row=i, column=0, sticky="w", pady=1)
            Tooltip(cb, tip)

        # ---- Output file ----
        sec5 = self._section(inner, "Output")
        tk.Label(sec5, text="JSON Report Path (optional)", bg=BG2, fg=TEXT2,
                 font=("Segoe UI", 8), anchor="w").grid(row=0, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self._output_var = tk.StringVar()
        oe = styled_entry(sec5, width=24)
        oe["textvariable"] = self._output_var
        oe.grid(row=1, column=0, sticky="ew")
        browse_btn = tk.Button(
            sec5, text="…", bg=BG3, fg=TEXT, relief="flat",
            font=("Segoe UI", 9), padx=6, cursor="hand2",
            command=self._browse_output
        )
        browse_btn.grid(row=1, column=1, padx=(4, 0))
        sec5.columnconfigure(0, weight=1)

        # ---- Action buttons ----
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=14, pady=(16, 0))
        btn_frame = tk.Frame(inner, bg=BG2)
        btn_frame.pack(fill="x", padx=14, pady=10)

        self._scan_btn = tk.Button(
            btn_frame, text="▶  Start Scan", bg=ACCENT2, fg=TEXT,
            relief="flat", font=("Segoe UI", 10, "bold"),
            padx=14, pady=8, cursor="hand2",
            command=self._start_scan, activebackground=ACCENT, activeforeground=TEXT
        )
        self._scan_btn.pack(fill="x", pady=(0, 6))

        self._stop_btn = tk.Button(
            btn_frame, text="⏹  Stop", bg=BG3, fg=TEXT2,
            relief="flat", font=("Segoe UI", 10),
            padx=14, pady=6, cursor="hand2",
            command=self._stop_scan, state="disabled",
            activebackground=BG3, activeforeground=TEXT
        )
        self._stop_btn.pack(fill="x")

        # Progress bar
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("S.Horizontal.TProgressbar",
                        troughcolor=BG3, background=ACCENT2, bordercolor=BG2,
                        lightcolor=ACCENT2, darkcolor=ACCENT2)
        self._progress = ttk.Progressbar(
            inner, mode="indeterminate", style="S.Horizontal.TProgressbar", length=200
        )
        self._progress.pack(fill="x", padx=14, pady=(6, 14))

    def _build_output_panel(self, parent):
        # Tab strip
        tab_bar = tk.Frame(parent, bg=BG2, height=36)
        tab_bar.pack(fill="x")
        tab_bar.pack_propagate(False)

        self._tab_content = tk.Frame(parent, bg=BG)
        self._tab_content.pack(fill="both", expand=True)

        self._active_tab = tk.StringVar(value="log")
        self._tab_frames = {}
        self._tab_btns = {}

        for name, label in [("log", "📋  Live Log"), ("findings", "🔍  Findings"), ("json", "{ }  JSON Report")]:
            btn = tk.Button(
                tab_bar, text=label, bg=BG2, fg=TEXT2,
                relief="flat", font=("Segoe UI", 9),
                padx=14, pady=0, cursor="hand2",
                command=lambda n=name: self._switch_tab(n),
                activebackground=BG, activeforeground=TEXT
            )
            btn.pack(side="left", fill="y")
            self._tab_btns[name] = btn

            frame = tk.Frame(self._tab_content, bg=BG)
            self._tab_frames[name] = frame

        self._build_log_tab(self._tab_frames["log"])
        self._build_findings_tab(self._tab_frames["findings"])
        self._build_json_tab(self._tab_frames["json"])
        self._switch_tab("log")

    def _switch_tab(self, name):
        self._active_tab.set(name)
        for n, f in self._tab_frames.items():
            f.pack_forget()
        self._tab_frames[name].pack(fill="both", expand=True)
        for n, b in self._tab_btns.items():
            if n == name:
                b.configure(bg=BG, fg=ACCENT, font=("Segoe UI", 9, "bold"))
            else:
                b.configure(bg=BG2, fg=TEXT2, font=("Segoe UI", 9))

    def _build_log_tab(self, parent):
        toolbar = tk.Frame(parent, bg=BG2, height=30)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        tk.Button(toolbar, text="Clear", bg=BG2, fg=TEXT3, relief="flat",
                  font=("Segoe UI", 8), padx=10, cursor="hand2",
                  command=self._clear_log, activebackground=BG3
                  ).pack(side="right", fill="y")

        self._log_text = tk.Text(
            parent, bg=BG, fg=TEXT, insertbackground=ACCENT,
            relief="flat", font=("Consolas", 9),
            wrap="word", state="disabled",
            selectbackground=BG3, selectforeground=TEXT,
            padx=10, pady=8
        )
        scroll = tk.Scrollbar(parent, bg=BG2, troughcolor=BG2, command=self._log_text.yview)
        scroll.pack(side="right", fill="y")
        self._log_text.pack(fill="both", expand=True)
        self._log_text["yscrollcommand"] = scroll.set

        # Configure text tags for colouring
        self._log_text.tag_configure("accent",    foreground=ACCENT)
        self._log_text.tag_configure("green",     foreground=GREEN)
        self._log_text.tag_configure("yellow",    foreground=YELLOW)
        self._log_text.tag_configure("red",       foreground=RED)
        self._log_text.tag_configure("orange",    foreground=ORANGE)
        self._log_text.tag_configure("purple",    foreground=PURPLE)
        self._log_text.tag_configure("dim",       foreground=TEXT3)
        self._log_text.tag_configure("bold",      font=("Consolas", 9, "bold"))
        self._log_text.tag_configure("heading",   foreground=ACCENT, font=("Consolas", 9, "bold"))

    def _build_findings_tab(self, parent):
        self._findings_canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        scroll = tk.Scrollbar(parent, orient="vertical", command=self._findings_canvas.yview)
        scroll.pack(side="right", fill="y")
        self._findings_canvas.pack(fill="both", expand=True)
        self._findings_canvas.configure(yscrollcommand=scroll.set)

        self._findings_inner = tk.Frame(self._findings_canvas, bg=BG)
        self._findings_win = self._findings_canvas.create_window((0, 0), window=self._findings_inner, anchor="nw")

        def on_config(e):
            self._findings_canvas.configure(scrollregion=self._findings_canvas.bbox("all"))
        def on_canvas_cfg(e):
            self._findings_canvas.itemconfig(self._findings_win, width=e.width)
        self._findings_inner.bind("<Configure>", on_config)
        self._findings_canvas.bind("<Configure>", on_canvas_cfg)
        self._findings_canvas.bind_all("<MouseWheel>",
            lambda e: self._findings_canvas.yview_scroll(-1*(e.delta//120), "units"))

        tk.Label(self._findings_inner, text="Run a scan to see findings.",
                 bg=BG, fg=TEXT3, font=("Segoe UI", 10), pady=30).pack()

    def _build_json_tab(self, parent):
        toolbar = tk.Frame(parent, bg=BG2, height=30)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        tk.Button(toolbar, text="Save As…", bg=BG2, fg=TEXT3, relief="flat",
                  font=("Segoe UI", 8), padx=10, cursor="hand2",
                  command=self._save_json, activebackground=BG3
                  ).pack(side="right", fill="y")

        self._json_text = tk.Text(
            parent, bg=BG, fg=GREEN, insertbackground=ACCENT,
            relief="flat", font=("Consolas", 9),
            wrap="none", state="disabled",
            selectbackground=BG3, selectforeground=TEXT,
            padx=10, pady=8
        )
        sy = tk.Scrollbar(parent, bg=BG2, troughcolor=BG2, command=self._json_text.yview)
        sx = tk.Scrollbar(parent, bg=BG2, troughcolor=BG2, orient="horizontal", command=self._json_text.xview)
        sy.pack(side="right", fill="y")
        sx.pack(side="bottom", fill="x")
        self._json_text.pack(fill="both", expand=True)
        self._json_text["yscrollcommand"] = sy.set
        self._json_text["xscrollcommand"] = sx.set

    # ------------------------------------------------------------------
    # Browse / save helpers
    # ------------------------------------------------------------------
    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save JSON Report As"
        )
        if path:
            self._output_var.set(path)

    def _save_json(self):
        if not self._result_data:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save JSON Report As"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._result_data, f, indent=2)
            messagebox.showinfo("Saved", f"Report saved to:\n{path}")

    # ------------------------------------------------------------------
    # Log helpers
    # ------------------------------------------------------------------
    def _clear_log(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")

    def _log(self, msg, tag=None):
        """Append a line to the log (thread-safe via queue)."""
        self._log_queue.put((msg, tag))

    def _poll_log_queue(self):
        try:
            while True:
                msg, tag = self._log_queue.get_nowait()
                self._append_log(msg, tag)
        except queue.Empty:
            pass
        self.after(50, self._poll_log_queue)

    def _append_log(self, msg, tag=None):
        self._log_text.configure(state="normal")
        # Auto-color based on content
        if tag is None:
            low = msg.lower()
            if "[!]" in msg or "confirmed" in low:
                tag = "red"
            elif "[+]" in msg or "likely" in low:
                tag = "orange"
            elif "[?]" in msg or "possible" in low:
                tag = "yellow"
            elif "[-]" in msg or "not_vulnerable" in low:
                tag = "green"
            elif "[crawl]" in low or "[fingerprint]" in low or "[scan]" in low or "[probe]" in low:
                tag = "heading"
            elif "•" in msg:
                tag = "dim"
            elif "==" in msg or "--" in msg:
                tag = "accent"
        self._log_text.insert("end", msg + "\n", tag or "")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Scan logic
    # ------------------------------------------------------------------
    def _start_scan(self):
        if self._running:
            return
        if SCANNER is None:
            messagebox.showerror("Error",
                "Cannot find php_app_cve_scanner.py in the same directory.")
            return

        url = self._url_var.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Please enter a target URL.")
            return

        # Validate numeric fields
        try:
            depth    = int(self._depth_var.get())
            maxpages = int(self._maxpages_var.get())
            timeout  = float(self._timeout_var.get())
            delay    = float(self._delay_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Depth, Max Pages, Timeout, Delay must be numbers.")
            return

        self._running = True
        self._result_data = None
        self._scan_btn.configure(state="disabled", bg=BG3)
        self._stop_btn.configure(state="normal", bg=RED)
        self._progress.start(12)
        self._status_var.set("Scanning…")
        self._elapsed_var.set("")
        self._clear_log()
        self._clear_findings()

        # Switch to log tab
        self._switch_tab("log")

        # Collect args
        args = {
            "url":        url,
            "depth":      depth,
            "max_pages":  maxpages,
            "timeout":    timeout,
            "delay":      delay,
            "cookie":     self._cookie_var.get().strip(),
            "header":     [self._header_var.get().strip()] if self._header_var.get().strip() else [],
            "ua":         self._ua_var.get().strip() or "PHP-App-CVE-Scanner/2.0",
            "secure":     self._secure_var.get(),
            "subdomains": self._subdomains_var.get(),
            "robots":     self._robots_var.get(),
            "aggressive": self._aggressive_var.get(),
            "only_2026":  self._only2026_var.get(),
            "quiet":      self._quiet_var.get(),
            "output":     self._output_var.get().strip(),
        }

        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(args,), daemon=True
        )
        self._scan_thread.start()

    def _stop_scan(self):
        """Signal the scan to stop (best-effort — we flag it via a sentinel)."""
        self._running = False
        self._log("⏹ Scan stop requested…", "yellow")
        self._scan_done()

    def _scan_done(self):
        self._running = False
        self._progress.stop()
        self._scan_btn.configure(state="normal", bg=ACCENT2)
        self._stop_btn.configure(state="disabled", bg=BG3)
        self._status_var.set("Done")

    def _parse_header_list(self, items):
        out = {}
        for item in items or []:
            if item and ":" in item:
                k, v = item.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    def _run_scan(self, args):
        """Runs in a background thread. Redirects stdout to log queue."""
        t0 = time.time()

        import re as _re
        import urllib.parse as _up

        # Redirect stdout
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        log_q = self._log_queue

        class QueueWriter:
            def write(self_, msg):
                if msg.strip():
                    log_q.put((msg.rstrip(), None))
            def flush(self_):
                pass

        sys.stdout = QueueWriter()
        sys.stderr = QueueWriter()

        try:
            target = args["url"]
            if not _re.match(r"^https?://", target, _re.I):
                target = "http://" + target
            p = _up.urlparse(target)
            if not p.netloc:
                self._log("❌ Invalid target URL", "red")
                return
            root = f"{p.scheme}://{p.netloc}/"

            self._log(f"[+] Target: {root}")
            if args["only_2026"]:
                self._log("[+] Mode: 2026 PHP CVEs only (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560)")

            client = SCANNER.HttpClient(
                timeout=args["timeout"],
                verify_ssl=bool(args["secure"]),
                user_agent=args["ua"],
                extra_headers=self._parse_header_list(args["header"]),
                cookie=args["cookie"],
                rate_delay=args["delay"],
            )

            probe = client.get(root)
            if probe.get("error") and probe.get("status") is None:
                self._log(f"[!] Cannot reach target: {probe['error']}", "red")
                return
            self._log(f"[+] Reachable (status={probe.get('status')})")

            if not self._running:
                return

            crawler = SCANNER.Crawler(
                root=root, client=client,
                max_pages=args["max_pages"],
                max_depth=args["depth"],
                include_subdomains=args["subdomains"],
                respect_robots=args["robots"],
                verbose=not args["quiet"],
            )
            crawler.crawl()

            if not self._running:
                return

            if not crawler.pages and probe.get("status"):
                crawler.pages.append({
                    "url": root, "final_url": probe.get("final_url") or root,
                    "status": probe.get("status"), "headers": probe.get("headers") or {},
                    "body": probe.get("body") or b"",
                    "text": (probe.get("body") or b"").decode("utf-8", errors="replace"),
                    "ct": (probe.get("headers") or {}).get("content-type", ""), "error": None,
                })

            fp = SCANNER.fingerprint(crawler, client)

            if not self._running:
                return

            scanner = SCANNER.Scanner(
                root, client, crawler, fp,
                aggressive=args["aggressive"],
                only_2026=args["only_2026"],
            )
            findings = scanner.run_all()
            elapsed = time.time() - t0
            report = SCANNER.print_report(root, fp, crawler, findings, elapsed)

            # Save JSON
            out = args["output"] or \
                f"php_cve_report_{p.netloc.replace(':', '_')}_{int(time.time())}.json"
            if not os.path.isabs(out):
                out = os.path.abspath(out)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            self._log(f"\n[+] JSON report → {out}")

            self._result_data = report

            # Schedule GUI update on main thread
            self.after(0, lambda: self._populate_findings(findings, fp, crawler, elapsed))
            self.after(0, lambda: self._populate_json(report))
            self.after(0, lambda: self._elapsed_var.set(f"Elapsed: {elapsed:.1f}s"))

        except Exception as exc:
            self._log(f"[ERROR] {exc}", "red")
            import traceback
            self._log(traceback.format_exc(), "red")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            self.after(0, self._scan_done)

    # ------------------------------------------------------------------
    # Findings panel population
    # ------------------------------------------------------------------
    def _clear_findings(self):
        for w in self._findings_inner.winfo_children():
            w.destroy()

    def _populate_findings(self, findings, fp, crawler, elapsed):
        self._clear_findings()
        if not findings:
            tk.Label(self._findings_inner, text="No findings.", bg=BG, fg=TEXT3,
                     font=("Segoe UI", 10), pady=30).pack()
            return

        # Summary banner
        n_c = sum(1 for f in findings if f.status == "CONFIRMED")
        n_l = sum(1 for f in findings if f.status == "LIKELY")
        n_p = sum(1 for f in findings if f.status == "POSSIBLE")
        n_nv = sum(1 for f in findings if f.status == "NOT_VULNERABLE")

        banner = tk.Frame(self._findings_inner, bg=BG2, pady=10)
        banner.pack(fill="x", padx=12, pady=(10, 4))

        for label, val, color in [
            ("CONFIRMED", n_c, RED),
            ("LIKELY",    n_l, ORANGE),
            ("POSSIBLE",  n_p, YELLOW),
            ("SAFE",      n_nv, GREEN),
        ]:
            pill = tk.Frame(banner, bg=color, padx=12, pady=4)
            pill.pack(side="left", padx=(0, 8))
            tk.Label(pill, text=f"{val}  {label}", bg=color, fg=BG,
                     font=("Segoe UI", 8, "bold")).pack()

        tk.Label(banner, text=f"  {elapsed:.1f}s  |  {len(crawler.pages)} pages  |  PHP {fp.php_version or 'unknown'}",
                 bg=BG2, fg=TEXT2, font=("Segoe UI", 8)).pack(side="left", padx=8)

        # Sort findings
        def rank(f):
            sr = {"CONFIRMED":0,"LIKELY":1,"POSSIBLE":2,"ERROR":3,"NOT_VULNERABLE":4,"NOT_APPLICABLE":5}.get(f.status,9)
            sev = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(f.severity,9)
            return (0 if f.cve.startswith("CVE-2026-") else 1, sr, sev, f.cve)

        sorted_findings = sorted(findings, key=rank)

        for f in sorted_findings:
            self._finding_card(self._findings_inner, f)

        # Switch to findings tab
        self.after(0, lambda: self._switch_tab("findings"))

    def _finding_card(self, parent, f):
        status_color = STATUS_COLOR.get(f.status, TEXT3)
        sev_color    = SEV_COLOR.get(f.severity, TEXT2)

        card = tk.Frame(parent, bg=BG2, bd=0, relief="flat")
        card.pack(fill="x", padx=12, pady=4)

        # Left accent bar
        bar = tk.Frame(card, bg=status_color, width=4)
        bar.pack(side="left", fill="y")

        body = tk.Frame(card, bg=BG2, padx=12, pady=8)
        body.pack(fill="x", expand=True)

        # Top row: CVE id + severity badge + status badge
        top = tk.Frame(body, bg=BG2)
        top.pack(fill="x")

        tk.Label(top, text=f.cve, bg=BG2, fg=ACCENT,
                 font=("Consolas", 10, "bold")).pack(side="left")

        sev_pill = tk.Label(top, text=f" {f.severity} ", bg=sev_color, fg=BG,
                            font=("Segoe UI", 7, "bold"), padx=4)
        sev_pill.pack(side="left", padx=(8, 4))

        stat_pill = tk.Label(top, text=f" {f.status} ", bg=status_color, fg=BG,
                             font=("Segoe UI", 7, "bold"), padx=4)
        stat_pill.pack(side="left")

        conf_lbl = tk.Label(top, text=f"  confidence: {f.confidence}",
                            bg=BG2, fg=TEXT3, font=("Segoe UI", 8))
        conf_lbl.pack(side="left")

        # Title
        tk.Label(body, text=f.title, bg=BG2, fg=TEXT,
                 font=("Segoe UI", 9), anchor="w", wraplength=700, justify="left"
                 ).pack(fill="x", pady=(3, 0))

        # Evidence
        if f.evidence:
            ev_frame = tk.Frame(body, bg=BG3, padx=8, pady=4)
            ev_frame.pack(fill="x", pady=(6, 2))
            tk.Label(ev_frame, text="Evidence", bg=BG3, fg=TEXT3,
                     font=("Segoe UI", 7, "bold")).pack(anchor="w")
            for ev in f.evidence[:6]:
                tk.Label(ev_frame, text=f"• {ev}", bg=BG3, fg=TEXT2,
                         font=("Consolas", 8), anchor="w", wraplength=700, justify="left"
                         ).pack(anchor="w")

        # Affected URLs
        if f.affected_urls:
            tk.Label(body, text="Affected: " + ", ".join(f.affected_urls[:3]),
                     bg=BG2, fg=ACCENT, font=("Segoe UI", 8), anchor="w",
                     wraplength=700, justify="left").pack(fill="x", pady=(2, 0))

        # Remediation
        if f.remediation:
            rem_frame = tk.Frame(body, bg=BG, padx=8, pady=4)
            rem_frame.pack(fill="x", pady=(4, 0))
            tk.Label(rem_frame, text="Remediation", bg=BG, fg=GREEN,
                     font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(rem_frame, text=f.remediation, bg=BG, fg=TEXT2,
                     font=("Segoe UI", 8), anchor="w", wraplength=700, justify="left"
                     ).pack(anchor="w")

        # Separator
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=12)

    # ------------------------------------------------------------------
    # JSON tab population
    # ------------------------------------------------------------------
    def _populate_json(self, report):
        self._json_text.configure(state="normal")
        self._json_text.delete("1.0", "end")
        self._json_text.insert("1.0", json.dumps(report, indent=2))
        self._json_text.configure(state="disabled")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    app = PhpScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
