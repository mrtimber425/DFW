# Digital Forensics Workbench (DFW)

The **Digital Forensics Workbench (DFW)** is a cross‑platform desktop
application designed to streamline common evidence analysis tasks for
digital forensic practitioners. It provides a unified, interactive GUI
for mounting disk images, searching for keywords, analysing memory
dumps, inspecting network captures and running Android artefact
parsers. DFW wraps a number of open source tools, exposing their
functionality through a consistent interface and consolidating
results into a single workspace.

## Features

- **Environment Detection** – displays information about the host
  operating system, whether the program is running under WSL, and
  which forensic command line tools are currently installed on the
  system.
- **Disk Image Mounting** – lists partitions inside raw disk images
  (e.g. `.dd` files) via `mmls` and allows you to mount a selected
  partition read‑only under Linux or extract its contents on Windows
  using the `pytsk3` library.
- **Keyword Search** – recursively scans directories for user‑defined
  keywords and displays a context snippet for each match.
- **Memory Analysis** – runs Volatility3 plugins against memory
  images; a variety of Windows and Linux plugins are provided by
  default and additional arguments may be supplied.
- **Network Analysis** – utilises `tshark` to summarise network
  captures (PCAP/PCAPNG) with per‑host statistics or full packet
  listings.
 - **Android Triage** – wraps `ALEAPP` to parse Android logs, events
  and protobuf data from an extraction or mounted image. (Optional –
  requires the `aleapp` tool to be installed separately.)
 - **File Timeline Generation** – produces a simple timeline from file
  system metadata. Unlike a full Plaso super‑timeline, this feature
  does not correlate events from disparate sources but offers a quick
  overview of file access, modification and creation times.
 - **Evidence OS Selection** – in the Case tab you can choose the
  operating system (Windows, Linux, Android or Auto) for the evidence
  you are examining. This filters available memory analysis plugins
  and simplifies the workflow.

## Prerequisites

DFW is written in Python and relies on the Tkinter GUI toolkit
(bundled with most Python distributions). In addition, it wraps a
number of external forensic tools. These tools **are not bundled** and
should be installed separately for full functionality. Without them
the GUI will still run, but certain features will be unavailable or
will show an error message.

 - **The Sleuth Kit** – provides `mmls` for partition discovery and,
  optionally, the `pytsk3` Python bindings for filesystem extraction.
  Note that `pytsk3` is **not included** in the default Python
  dependencies for Windows because it requires the Microsoft Visual
  C++ Build Tools to compile. If you wish to extract files from
  images on Windows, install the build tools and then run
  `pip install pytsk3` in your virtual environment.
- **Volatility3** – memory analysis framework.
 - **Wireshark** – provides `tshark` for network capture analysis.
 - **ALEAPP** – Android Logs Events And Protobuf Parser (optional; if
  not installed the Android tab will show a tool‑not‑available error).

On Debian/Ubuntu systems the following commands will install the
necessary dependencies:

```bash
sudo apt update
sudo apt install sleuthkit python3-pytsk3 wireshark tshark
pip install volatility3
```

On Windows you can install packages via winget or chocolatey and
``pip``. Ensure that the tools are added to your ``PATH``.
If you require `pytsk3` on Windows you must first install the
**Microsoft Visual C++ Build Tools** and then run `pip install
pytsk3`. Without it, extraction of filesystem contents on Windows
will be unavailable.

## Installation

Clone or download this repository and create a virtual environment
for isolation. You can either install dependencies manually or use
the provided installer script:

### Using the Installer Script

To automate setup, run the included `install_dfw.py` script. It
detects your operating system, creates a virtual environment, installs
the required Python packages and (optionally) launches the GUI. For
example:

```bash
python install_dfw.py --venv-name dfw_env --run
```

This command will create or reuse a virtual environment called
`dfw_env`, install `volatility3` into it and start the workbench. The
installer also prints guidance on installing external tools. Use the
`--no-install` flag if you have already installed the requirements
manually.

### Manual Installation

If you prefer manual installation, activate your virtual
environment and run:

```bash
pip install -r requirements.txt
```

By default `requirements.txt` includes only `volatility3`. Other
packages such as `pytsk3` and `aleapp` are optional and must be
installed separately if needed.

## Usage

Run the application using the Python module syntax:

```bash
python -m dfw
```

Alternatively you can execute the script directly:

```bash
python dfw/main.py
```

The GUI will open with six tabs. Begin by entering your case
information and refreshing the environment info. Specify the
**Evidence OS** (Auto/Windows/Linux/Android) in the Case tab to
filter memory plugins appropriate for your evidence. Then proceed to
mount disk images, search for keywords, analyse memory, inspect
network captures, parse Android artefacts or generate a simple
timeline from file metadata as needed.

## Limitations and Notes

- Mounting partitions with the system `mount` command requires
  administrative privileges on Linux. Run the application with
  sufficient privileges or configure `sudo` accordingly.
- On Windows the application cannot mount raw disk images directly.
  Instead it extracts files via `pytsk3`. This can be time
  consuming for large partitions.
- Forensic tool wrappers simply capture and display stdout/stderr.
  They do not parse or interpret the data; however, you can copy
  results for further analysis.
 - The built‑in timeline generator is simple and based on file
  metadata. For more sophisticated event correlation you may wish to
  explore external tools such as Plaso or The Sleuth Kit's
  `mactime` outside of the application.

## License

This project is provided under the MIT License. See `LICENSE` for
details.