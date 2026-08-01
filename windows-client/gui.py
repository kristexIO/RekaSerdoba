import os
import json
import subprocess
import threading
import time
import tkinter as tk
from pathlib import Path

from version import VERSION

BG = "#111416"
SIDEBAR = "#171b1e"
PANEL = "#1b2024"
PANEL_ALT = "#20262a"
BORDER = "#30383d"
TEXT = "#e4e8ea"
MUTED = "#8d989f"
ACCENT = "#78909c"
ACCENT_HOVER = "#879da8"
ACTIVE = "#77907d"
WARNING = "#a7896a"
SERVICE = "RekaSerdoba"
ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / SERVICE
LOG_PATH = ROOT / "service.log"
POLICY_STATE = ROOT / "network-policy.json"
SETTINGS = ROOT / "settings.json"
STATUS = ROOT / "status.json"


def rounded(canvas, coordinates, radius, **options):
    x1, y1, x2, y2 = coordinates
    points = [
        x1 + radius,
        y1,
        x2 - radius,
        y1,
        x2,
        y1,
        x2,
        y1 + radius,
        x2,
        y2 - radius,
        x2,
        y2,
        x2 - radius,
        y2,
        x1 + radius,
        y2,
        x1,
        y2,
        x1,
        y2 - radius,
        x1,
        y1 + radius,
        x1,
        y1,
    ]
    return canvas.create_polygon(points, smooth=True, **options)


def service_status():
    result = subprocess.run(
        ["sc.exe", "query", SERVICE],
        check=False,
        capture_output=True,
        text=True,
        creationflags=0x08000000,
    )
    if result.returncode != 0:
        return "missing"
    if "RUNNING" in result.stdout:
        try:
            state = json.loads(STATUS.read_text(encoding="utf-8"))
            fresh = int(time.time()) - int(state.get("updated_at", 0)) < 30
            current = state.get("state")
        except (OSError, ValueError, TypeError):
            fresh = False
            current = None
        return "connected" if fresh and current == "connected" else "connecting"
    return "stopped"


def read_log():
    try:
        return LOG_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_transport_mode():
    try:
        mode = str(
            json.loads(SETTINGS.read_text(encoding="utf-8")).get("transport", "auto")
        ).lower()
    except (OSError, ValueError, TypeError):
        mode = "auto"
    return mode if mode in {"auto", "h3", "h2", "wss"} else "auto"


def write_transport_mode(mode):
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    temporary = SETTINGS.with_suffix(".new")
    temporary.write_text(
        json.dumps({"transport": mode}, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(temporary, SETTINGS)


class RekaGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RekaSerdoba")
        self.root.geometry("1060x700")
        self.root.minsize(920, 620)
        self.root.configure(bg=BG)
        self.root.option_add("*Font", ("Segoe UI", 10))
        self.started_at = None
        self.last_state = None
        self.busy = False
        self.page = "home"
        self.transport_mode = read_transport_mode()
        self.build()
        self.refresh()

    def build(self):
        self.sidebar = tk.Frame(self.root, bg=SIDEBAR, width=78)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        logo = tk.Canvas(
            self.sidebar, width=46, height=46, bg=SIDEBAR, highlightthickness=0
        )
        logo.pack(pady=(20, 28))
        rounded(logo, (2, 2, 44, 44), 13, fill=PANEL_ALT, outline=BORDER)
        logo.create_text(23, 23, text="R", fill=TEXT, font=("Segoe UI Semibold", 18))
        self.home_button = self.nav_button("⌂", "Главная", self.show_home)
        self.log_button = self.nav_button("≡", "Журнал", self.show_logs)
        self.sidebar_spacer = tk.Frame(self.sidebar, bg=SIDEBAR)
        self.sidebar_spacer.pack(fill="both", expand=True)
        tk.Label(
            self.sidebar,
            text=VERSION,
            bg=SIDEBAR,
            fg="#59636a",
            font=("Segoe UI", 8),
        ).pack(pady=18)
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)
        self.header = tk.Frame(self.content, bg=BG, height=100)
        self.header.pack(fill="x", padx=30)
        self.header.pack_propagate(False)
        title_box = tk.Frame(self.header, bg=BG)
        title_box.pack(side="left", pady=(14, 0))
        self.title = tk.Label(
            title_box,
            text="Главная",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI Semibold", 21),
        )
        self.title.pack(anchor="w")
        tk.Label(
            title_box,
            text="Защищённое подключение",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(2, 0))
        self.header_state = tk.Label(
            self.header,
            text="●  Отключено",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI Semibold", 10),
        )
        self.header_state.pack(side="right", pady=28)
        self.body = tk.Frame(self.content, bg=BG)
        self.body.pack(fill="both", expand=True, padx=30, pady=(0, 30))
        self.home = tk.Frame(self.body, bg=BG)
        self.logs = tk.Frame(self.body, bg=BG)
        self.build_home()
        self.build_logs()
        self.show_home()

    def nav_button(self, symbol, label, command):
        frame = tk.Frame(self.sidebar, bg=SIDEBAR)
        frame.pack(fill="x", pady=4)
        button = tk.Button(
            frame,
            text=symbol,
            command=command,
            bg=SIDEBAR,
            activebackground=PANEL_ALT,
            fg=MUTED,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            font=("Segoe UI Symbol", 20),
            cursor="hand2",
            width=3,
            height=1,
        )
        button.pack(padx=9, pady=3)
        button.bind("<Enter>", lambda event: self.root.title(f"RekaSerdoba — {label}"))
        button.bind("<Leave>", lambda event: self.root.title("RekaSerdoba"))
        return button

    def build_home(self):
        self.home.pack(fill="both", expand=True)
        self.connection_card = tk.Canvas(
            self.home, bg=BG, highlightthickness=0, height=375
        )
        self.connection_card.pack(fill="x")
        self.connection_card.bind("<Configure>", self.draw_connection)
        mode_bar = tk.Frame(
            self.home,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
            padx=18,
            pady=12,
        )
        mode_bar.pack(fill="x", pady=(14, 0))
        tk.Label(
            mode_bar,
            text="Режим подключения",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI Semibold", 9),
        ).pack(side="left")
        self.mode_buttons = {}
        for mode, title in reversed(
            (("auto", "Авто"), ("h3", "H3"), ("h2", "H2"), ("wss", "WSS"))
        ):
            button = tk.Button(
                mode_bar,
                text=title,
                command=lambda value=mode: self.set_transport_mode(value),
                relief="flat",
                bd=0,
                width=8,
                pady=7,
                cursor="hand2",
                font=("Segoe UI Semibold", 9),
            )
            button.pack(side="right", padx=(7, 0))
            self.mode_buttons[mode] = button
        self.update_mode_buttons()
        cards = tk.Frame(self.home, bg=BG)
        cards.pack(fill="both", expand=True, pady=(14, 0))
        self.server_card = self.info_card(cards, "СЕРВЕР", "messk.online", "31.56.188.92")
        self.server_card.pack(side="left", fill="both", expand=True, padx=(0, 9))
        self.transport_value = tk.StringVar(value="Ожидание")
        self.transport_card = self.info_card(
            cards, "ТРАНСПОРТ", self.transport_value, "H3 → H2 → WSS"
        )
        self.transport_card.pack(side="left", fill="both", expand=True, padx=(9, 0))

    def info_card(self, parent, heading, value, detail):
        frame = tk.Frame(
            parent,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
            padx=22,
            pady=18,
        )
        tk.Label(
            frame,
            text=heading,
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w")
        tk.Label(
            frame,
            textvariable=value if isinstance(value, tk.StringVar) else None,
            text="" if isinstance(value, tk.StringVar) else value,
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI Semibold", 15),
        ).pack(anchor="w", pady=(10, 3))
        tk.Label(
            frame,
            text=detail,
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w")
        return frame

    def draw_connection(self, event=None):
        canvas = self.connection_card
        width = max(canvas.winfo_width(), 400)
        canvas.delete("all")
        rounded(canvas, (1, 1, width - 1, 374), 22, fill=PANEL, outline=BORDER)
        state = self.current_state()
        connected = state == "connected"
        connecting = state == "connecting"
        color = ACTIVE if connected else ACCENT
        canvas.create_oval(
            width / 2 - 74,
            48,
            width / 2 + 74,
            196,
            fill=PANEL_ALT,
            outline=color,
            width=3,
            tags="power",
        )
        canvas.create_arc(
            width / 2 - 27,
            91,
            width / 2 + 27,
            151,
            start=210,
            extent=300,
            style="arc",
            outline=color,
            width=5,
            tags="power",
        )
        canvas.create_line(
            width / 2,
            75,
            width / 2,
            119,
            fill=color,
            width=5,
            capstyle="round",
            tags="power",
        )
        if connected:
            heading = "Подключено"
            detail = "Трафик защищён и направлен через RekaSerdoba"
        elif connecting:
            heading = "Подключение…"
            detail = "Проверяем сервер и подготавливаем безопасный маршрут"
        elif state == "missing":
            heading = "Клиент не установлен"
            detail = "Запустите установщик RekaSerdoba"
        else:
            heading = "Отключено"
            detail = "Обычное подключение к интернету активно"
        canvas.create_text(
            width / 2,
            232,
            text=heading,
            fill=TEXT,
            font=("Segoe UI Semibold", 20),
        )
        canvas.create_text(
            width / 2,
            264,
            text=detail,
            fill=MUTED,
            font=("Segoe UI", 10),
        )
        action = "Отключить" if connected or connecting else "Подключить"
        x1, x2 = width / 2 - 118, width / 2 + 118
        rounded(canvas, (x1, 304, x2, 352), 14, fill=color, outline=color, tags="action")
        canvas.create_text(
            width / 2,
            328,
            text="Подождите…" if self.busy else action,
            fill="#101416",
            font=("Segoe UI Semibold", 11),
            tags="action",
        )
        canvas.tag_bind("action", "<Button-1>", lambda event: self.toggle())
        canvas.tag_bind("power", "<Button-1>", lambda event: self.toggle())
        canvas.configure(cursor="hand2")

    def build_logs(self):
        toolbar = tk.Frame(self.logs, bg=BG)
        toolbar.pack(fill="x", pady=(0, 12))
        tk.Label(
            toolbar,
            text="Последние события службы",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
        ).pack(side="left")
        tk.Button(
            toolbar,
            text="Обновить",
            command=self.update_log_widget,
            bg=PANEL_ALT,
            activebackground=BORDER,
            fg=TEXT,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
        ).pack(side="right")
        tk.Button(
            toolbar,
            text="Копировать всё",
            command=self.copy_logs,
            bg=PANEL_ALT,
            activebackground=BORDER,
            fg=TEXT,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
        ).pack(side="right", padx=(0, 8))
        self.log_text = tk.Text(
            self.logs,
            bg=PANEL,
            fg="#bec6ca",
            insertbackground=TEXT,
            selectbackground="#3c4b53",
            relief="flat",
            bd=0,
            padx=20,
            pady=18,
            font=("Cascadia Mono", 9),
            wrap="word",
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")
        self.log_text.bind("<Control-c>", self.copy_selection)
        self.log_text.bind("<Button-3>", self.show_log_menu)
        self.log_menu = tk.Menu(
            self.root,
            tearoff=False,
            bg=PANEL_ALT,
            fg=TEXT,
            activebackground=BORDER,
            activeforeground=TEXT,
        )
        self.log_menu.add_command(label="Копировать", command=self.copy_selection)
        self.log_menu.add_command(label="Копировать всё", command=self.copy_logs)

    def show_home(self):
        self.page = "home"
        self.logs.pack_forget()
        self.home.pack(fill="both", expand=True)
        self.title.configure(text="Главная")
        self.home_button.configure(bg=PANEL_ALT, fg=TEXT)
        self.log_button.configure(bg=SIDEBAR, fg=MUTED)

    def show_logs(self):
        self.page = "logs"
        self.home.pack_forget()
        self.logs.pack(fill="both", expand=True)
        self.title.configure(text="Журнал")
        self.home_button.configure(bg=SIDEBAR, fg=MUTED)
        self.log_button.configure(bg=PANEL_ALT, fg=TEXT)
        self.update_log_widget()

    def current_state(self):
        return self.last_state or service_status()

    def toggle(self):
        if self.busy or self.current_state() == "missing":
            return
        command = "stop" if self.current_state() in {"connected", "connecting"} else "start"
        self.busy = True
        self.draw_connection()
        threading.Thread(target=self.run_command, args=(command,), daemon=True).start()

    def set_transport_mode(self, mode):
        if self.busy or mode == self.transport_mode:
            return
        self.transport_mode = mode
        write_transport_mode(mode)
        self.update_mode_buttons()
        if self.current_state() in {"connected", "connecting"}:
            self.busy = True
            self.draw_connection()
            threading.Thread(target=self.restart_service, daemon=True).start()

    def update_mode_buttons(self):
        for mode, button in self.mode_buttons.items():
            active = mode == self.transport_mode
            button.configure(
                bg=ACCENT if active else PANEL_ALT,
                fg=BG if active else TEXT,
                activebackground=ACCENT_HOVER if active else BORDER,
                activeforeground=BG if active else TEXT,
            )

    def restart_service(self):
        executable = Path(sys_executable_dir()) / "reka-service.exe"
        result = subprocess.run(
            [str(executable), "restart"],
            check=False,
            capture_output=True,
            text=True,
            creationflags=0x08000000,
        )
        self.root.after(0, lambda: self.command_finished(result))

    def run_command(self, command):
        executable = Path(sys_executable_dir()) / "reka-service.exe"
        result = subprocess.run(
            [str(executable), command],
            check=False,
            capture_output=True,
            text=True,
            creationflags=0x08000000,
        )
        self.root.after(0, lambda: self.command_finished(result))

    def command_finished(self, result):
        self.busy = False
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "Неизвестная ошибка").strip()
            self.show_error(message)
        self.refresh_now()

    def show_error(self, text):
        window = tk.Toplevel(self.root)
        window.title("RekaSerdoba")
        window.configure(bg=PANEL)
        window.resizable(False, False)
        window.transient(self.root)
        window.grab_set()
        tk.Label(
            window,
            text="Не удалось выполнить действие",
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI Semibold", 13),
        ).pack(anchor="w", padx=24, pady=(22, 8))
        tk.Label(
            window,
            text=text,
            bg=PANEL,
            fg=MUTED,
            wraplength=430,
            justify="left",
        ).pack(anchor="w", padx=24)
        tk.Button(
            window,
            text="Закрыть",
            command=window.destroy,
            bg=ACCENT,
            fg=BG,
            relief="flat",
            padx=22,
            pady=8,
        ).pack(anchor="e", padx=24, pady=22)

    def update_log_widget(self):
        text = read_log()
        lines = text.splitlines()[-300:]
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", "\n".join(lines) or "Событий пока нет.")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def copy_selection(self, event=None):
        try:
            value = self.log_text.get("sel.first", "sel.last")
        except tk.TclError:
            value = self.log_text.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        return "break"

    def copy_logs(self):
        value = self.log_text.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(value)

    def show_log_menu(self, event):
        self.log_menu.tk_popup(event.x_root, event.y_root)

    def refresh_now(self):
        state = service_status()
        if state != self.last_state:
            if state == "connected":
                self.started_at = time.monotonic()
            elif state != "connecting":
                self.started_at = None
            self.last_state = state
        if state == "connected":
            elapsed = int(time.monotonic() - (self.started_at or time.monotonic()))
            status = f"●  Подключено  {elapsed // 60:02d}:{elapsed % 60:02d}"
            color = ACTIVE
        elif state == "connecting":
            status, color = "●  Подключение", WARNING
        elif state == "missing":
            status, color = "●  Не установлено", WARNING
        else:
            status, color = "●  Отключено", MUTED
        self.header_state.configure(text=status, fg=color)
        try:
            runtime = json.loads(STATUS.read_text(encoding="utf-8"))
            transport = str(runtime.get("carrier", "Ожидание")).upper()
        except (OSError, ValueError, TypeError):
            transport = "Ожидание"
        self.transport_value.set(transport)
        self.draw_connection()
        if self.page == "logs":
            self.update_log_widget()

    def refresh(self):
        self.refresh_now()
        self.root.after(1000, self.refresh)

    def run(self):
        self.root.mainloop()


def sys_executable_dir():
    import sys

    return Path(sys.executable).resolve().parent


if __name__ == "__main__":
    RekaGui().run()
