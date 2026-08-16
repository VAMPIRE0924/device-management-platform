import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import xtermCSS from "@xterm/xterm/css/xterm.css?inline";

type ServerMessage = {
  type: "ready" | "output" | "error" | "closed";
  data?: string;
  code?: string;
  message?: string;
  fingerprint?: string;
};

const style = document.createElement("style");
style.textContent = xtermCSS;
document.head.appendChild(style);

const terminalHost = document.querySelector<HTMLDivElement>("#terminal")!;
const form = document.querySelector<HTMLFormElement>("#auth")!;
const authShell = document.querySelector<HTMLElement>("#authShell")!;
const status = document.querySelector<HTMLElement>("#status")!;
const username = document.querySelector<HTMLInputElement>("#username")!;
const password = document.querySelector<HTMLInputElement>("#password")!;
const connect = document.querySelector<HTMLButtonElement>("#connect")!;

const terminal = new Terminal({
  cursorBlink: true,
  cursorStyle: "block",
  convertEol: false,
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  fontSize: 14,
  lineHeight: 1.25,
  scrollback: 5000,
  theme: {
    background: "#071317",
    foreground: "#d8eeeb",
    cursor: "#62ddd1",
    cursorAccent: "#071317",
    selectionBackground: "#1d5e67aa",
    black: "#071317",
    brightBlack: "#50676a",
    green: "#6ed7a7",
    brightGreen: "#8ae9be",
    cyan: "#61d5ca",
    brightCyan: "#86eee5",
    white: "#d8eeeb",
    brightWhite: "#f4fffd",
  },
});
const fit = new FitAddon();
terminal.loadAddon(fit);
terminal.open(terminalHost);

let socket: WebSocket | null = null;
let serverError = "";
let autoConnect = form.dataset.autoConnect === "true";
let resizeFrame = 0;

const sendResize = () => {
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "resize", columns: terminal.cols, rows: terminal.rows }));
  }
};

const fitTerminal = () => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => {
    fit.fit();
  });
};

const resizeObserver = new ResizeObserver(() => fitTerminal());
resizeObserver.observe(terminalHost);
terminal.onResize(sendResize);
terminal.onData((data) => {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "input", data }));
});
fitTerminal();

form.addEventListener("submit", (event) => {
  event.preventDefault();
  serverError = "";
  status.textContent = "正在连接…";
  connect.disabled = true;
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const payload = {
    type: "auth",
    method: autoConnect ? "stored" : "password",
    username: username.value,
    password: password.value,
    columns: terminal.cols,
    rows: terminal.rows,
  };
  socket = new WebSocket(`${protocol}://${location.host}${location.pathname}/ws`);
  socket.addEventListener("open", () => {
    socket?.send(JSON.stringify(payload));
    payload.username = "";
    payload.password = "";
    username.value = "";
    password.value = "";
  });
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(String(event.data)) as ServerMessage;
    if (message.type === "output") {
      terminal.write(message.data || "");
      return;
    }
    if (message.type === "ready") {
      status.textContent = "已连接";
      authShell.classList.add("hidden");
      requestAnimationFrame(() => {
        fitTerminal();
        terminal.focus();
      });
      return;
    }
    if (message.type === "closed") {
      status.textContent = message.message || "SSH 会话已结束";
      terminal.write(`\r\n\x1b[90m${message.message || "SSH 会话已结束"}\x1b[0m\r\n`);
      return;
    }
    serverError = message.message || message.code || "连接失败";
    status.textContent = serverError;
    if (message.fingerprint) terminal.writeln(`\r\n主机密钥指纹: ${message.fingerprint}`);
  });
  socket.addEventListener("error", () => {
    if (!serverError) {
      serverError = "无法建立连接";
      status.textContent = serverError;
    }
  });
  socket.addEventListener("close", (event) => {
    connect.disabled = false;
    if (!authShell.classList.contains("hidden") && !serverError) {
      status.textContent = event.code === 1000 ? event.reason || "已断开" : `连接异常中断（${event.code}）`;
    }
  });
});

if (autoConnect) {
  form.dispatchEvent(new Event("submit", { cancelable: true }));
  autoConnect = false;
}
