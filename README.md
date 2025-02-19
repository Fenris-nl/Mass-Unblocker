# Executable Unblocker

Welcome to the **Executable Unblocker** project – a Python-based Tkinter GUI tool designed to scan, display, and unblock Windows executable files that may be blocked due to security settings. This application is built using `ttkbootstrap` for a modern look and feel, and it provides a user-friendly interface for managing executable files efficiently.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Detailed UI Components](#detailed-ui-components)
- [Underlying Mechanisms](#underlying-mechanisms)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

The Executable Unblocker is designed to help users quickly identify and unblock executables that have been blocked by Windows security measures, such as the Zone.Identifier alternate data stream. This tool is ideal for both casual users and system administrators who need a visual interface for managing executable files.

## Features

- **Graphical Interface:** Utilizes Tkinter and `ttkbootstrap` for a visually appealing and modern user interface.
- **Dual View Modes:** Offers both a detailed list view and an icon view for browsing files, catering to different user preferences.
- **Dynamic Scanning:** Scans specified directories for `.exe` files, displaying key details such as file size, last modification date, and block status.
- **Real-time Progress Monitoring:** Features a progress bar and a cancelable progress dialog during scanning and unblocking operations.
- **Action History:** Includes undo/redo functionality for unblocking actions, enhancing user control.
- **Data Export:** Allows exporting file details to CSV or JSON formats for documentation, reporting, and further analysis.
- **Context Menus:** Provides right-click context menus for quick access to actions like opening the containing folder or copying the file path.
- **Comprehensive Logging:** Implements detailed logging to both a file (`app.log`) and the console, aiding in debugging and monitoring.
- **Keyboard Shortcuts:** Supports keyboard shortcuts for common actions like refreshing the list (`F5`), selecting all (`Ctrl+A`), and deselecting all (`Ctrl+D`).

## Installation

### Prerequisites

- Python 3.x
- Required Python libraries:
  - tkinter (usually included with Python)
  - [ttkbootstrap](https://pypi.org/project/ttkbootstrap/): For enhanced UI theming.
  - [Pillow](https://pypi.org/project/Pillow/): For image handling, particularly for the splash screen and icons.

### Setup

1. Clone or download this repository to your local machine.
2. Install the required dependencies using pip:
   ```bash
   pip install ttkbootstrap Pillow
   ```
3. Ensure you have appropriate permissions to scan and modify files in the directories you intend to use.

## Usage

1. Run the application by executing:
   ```bash
   python main.py
   ```
2. Upon launching, the application will:
   - Display a splash screen for a few seconds.
   - Automatically scan a default directory for executable files.
3. To change the directory being scanned:
   - Use the "Browse" button in the toolbar or the "Select Directory" option in the File menu.
   - Enter the desired directory path in the directory entry field and press Enter or click "Refresh List".
4. Switch between list and icon views using the "Toggle View" button to suit your browsing preference.
5. To unblock files:
   - In list view, select one or more files and click "Unblock Selected".
   - In icon view, toggle the selection of files by clicking on their icons and then click "Unblock Selected".
   - To unblock all blocked files, click "Unblock All".
6. Export file details using the options in the "Export" menu to save data in CSV or JSON format.

## Detailed UI Components

- **Menubar:**

  - _File Menu:_ Options to select a directory, refresh the file list, and exit the application.
  - _Edit Menu:_ Provides "Undo" and "Redo" options for unblocking actions.
  - _Themes Menu:_ Allows changing the application's theme using `ttkbootstrap` themes.
  - _Export Menu:_ Options to export the file list to CSV or JSON.
  - _Help Menu:_ Includes an "About" section with application details and developer contact information.

- **Top Toolbar:**

  - _Directory Entry:_ A field to display and manually enter the directory path to scan.
  - _Browse Button:_ Opens a directory selection dialog.
  - _Refresh List Button:_ Refreshes the file list.
  - _Select All Button:_ Selects all files in the current view.
  - _Deselect All Button:_ Deselects all files in the current view.
  - _Unblock Selected Button:_ Unblocks the selected files.
  - _Unblock All Button:_ Unblocks all blocked files in the list.
  - _Toggle View Button:_ Switches between list and icon views.
  - _Cancel Scan Button:_ Cancels the current directory scan.

- **Search Bar:**

  - _Filter Entry:_ Allows filtering files by name. Type in the entry and click "Apply Filter".

- **Shortcuts Panel:**

  - _Displays a list of available keyboard shortcuts for quick navigation and actions._

- **Main Content Area:**

  - _List View (Treeview):_ Displays file details in a tabular format, including file path, size, modification date, and status. Supports sorting by column.
  - _Icon View:_ Displays files as icons, showing their block status visually.

- **Details Frame:**

  - _Displays detailed information about the selected file, including its full path, size, last modification time, and block status._

- **Status Bar:**
  - _Displays the current status of the application, including scan progress, total files, blocked files, and selected files._

## Underlying Mechanisms

- **File Scanning:**

  - The `FileScanner` class scans directories for `.exe` files and gathers file details.
  - It uses `os.walk` to traverse directories and `os.stat` to retrieve file metadata.
  - The `is_file_blocked` function checks for the presence of the Zone.Identifier stream to determine the block status.

- **Unblocking Files:**

  - The `unblock_file` function attempts to remove the Zone.Identifier stream from a file.
  - The `UnblockAction` class encapsulates the unblocking action for undo/redo functionality.

- **Virtual Treeview:**

  - The `VirtualTreeView` class efficiently handles large datasets by only displaying a subset of items at a time.

- **Icon View Arrangement:**
  - The `arrange_icons` function dynamically arranges icons in the icon view based on the available width.

## Troubleshooting

- **Scanning Issues:**

  - Ensure you have the necessary permissions to access and read the files in the selected directory.
  - If the scan seems to hang, try canceling and restarting it.

- **Unblocking Issues:**

  - Verify that the file is indeed blocked by checking for the Zone.Identifier stream manually.
  - Ensure you have write permissions to the file.

- **GUI Issues:**

  - Check the `app.log` file for any error messages or exceptions.
  - Ensure that all required dependencies are installed correctly.

- **Performance Issues:**
  - Scanning large directories may take time. Consider breaking down the scan into smaller directories.
  - The virtual treeview helps mitigate performance issues with large file lists, but very large directories may still cause delays.

## Contributing

Contributions are welcome! If you have ideas for improvements, bug fixes, or additional features:

- Fork the repository.
- Create a new branch for your feature or bug fix.
- Submit a pull request with a clear description of your changes.

## License

This project is open-source and available under the MIT License. You are free to use, modify, and distribute it according to the terms of the license.

## Contact

For questions, support, or further information, please contact:

- **Email:** [kaanerdem3@gmail.com](mailto:kaanerdem3@gmail.com)
- **GitHub:** [Fenris-nl](https://github.com/Fenris-nl)

---

_Thank you for using Executable Unblocker! We hope it simplifies your file management tasks._
