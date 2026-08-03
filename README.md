# Zero-Leak E2E Encrypted Messenger

> A forensically hardened Python messaging engine engineered to defeat CPython memory persistence, OS swap-space paging, and display server frame-buffer leaks.

---

## Overview

High-level interpreted languages like Python make memory management invisible to the developer. Standard garbage collection, immutable strings, and framework UI caches (`pymalloc` heap retention, widget undo stacks, OpenGL frame buffers) leave plaintext data sitting in RAM long after messages are deleted on-screen.

This project implements a **zero-leak security architecture** that forces absolute memory hygiene at the application, runtime, and OS layers.

---

## Key Security Features

* **Double Ratchet Cryptography:** Implements continuous symmetric-key rotation per message, delivering **Perfect Forward Secrecy (PFS)** and post-compromise security.
* **In-Place Memory Shredder (`ctypes`):** Bypasses CPython's `pymalloc` heap retention by targeting raw C-level memory addresses and overwriting RAM in-place with multi-pass random byte streams and zero-bytes (`0x00`).
* **UI & Graphics Buffer Purging:** Overrides Kivy and SDL2 lifecycle handlers to scrub `_undo_history` caches, text input queues, and OpenGL frame buffers upon message deletion.
* **Process Anti-Swapping (`mlockall`):** Invokes `libc.mlockall()` to lock process memory in RAM, preventing the OS kernel from paging sensitive plaintext onto disk swap partitions.
* **Forensic Verification:** Validated via live Linux kernel dumps (`gcore`), `gdb`, and hex-level memory sweeps across UTF-8, UCS-2, and UCS-4 encodings—returning **zero forensic artifacts** after execution of the burn sequence.

---

## Tech Stack

* **Language:** Python 3.10+
* **Low-Level & C-Bindings:** `ctypes`, `libc`
* **Cryptography:** Double Ratchet Protocol, AES-256-GCM / ChaCha20-Poly1305
* **GUI / Graphics:** Kivy, Cython, SDL2 / OpenGL
* **Forensics & Audit Tooling:** `gcore`, `gdb`, `hexdump`
* **Target OS:** Linux (Debian / Kali / Ubuntu)

---

## Quickstart

### Prerequisites
Make sure you have Python 3.10+ installed on a Linux environment.

```bash
# 1. Clone the repository
git clone [https://github.com/YOUR_USERNAME/zero_leak_messenger.git](https://github.com/YOUR_USERNAME/zero_leak_messenger.git)
cd zero_leak_messenger

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py



