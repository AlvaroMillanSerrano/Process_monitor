# Process_monitor
A program that allows the user to analyze the processes running in his machine, detailed and with the capacity of searching anomalies

# Usage
Create a virtual enviroment where dependencies will be installed installed:
- **Linux / macOS:**
  ```bash
  python3 -m venv .venv
  ```
- **Windows:**
  ```bash
  python -m venv .venv
  ```

Activate the .venv:
- **Linux / macOS:**
  ```bash
  source .venv/bin/activate
  ```
- **Windows (PowerShell):**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```
- **Windows (CMD):**
  ```cmd
  .\.venv\Scripts\activate.bat
  ```

With the venv active, install the project dependencies (`-e`):
```bash
pip install -e .
```

Run the script:
- **Linux / macOS:**
  ```bash
  sudo .venv/bin/python code/script.py
  ```
- **Windows:**
  *(Remember opening cmd with administrator)*
  ```bash
  python code\script.py
  ```
