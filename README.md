# EXE String Editor

A Windows application that allows you to analyze EXE files, extract all strings, and replace them with new text.

## Features

- Modern and user-friendly interface
- Extract all strings from EXE files
- Replace strings with new text
- Automatic backup creation before modifications
- Support for UTF-8 encoded strings

## Installation

1. Make sure you have Python 3.7 or higher installed
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   python exe_string_editor.py
   ```
2. Click "Select EXE File" to choose an EXE file to analyze
3. The application will display all found strings in the main window
4. To replace a string:
   - Enter the old string in the "Old String" field
   - Enter the new string in the "New String" field
   - Click "Replace"
   - A backup of the original file will be created automatically

## Notes

- The new string cannot be longer than the old string
- A backup file (with .backup extension) is created before any modifications
- Only printable strings with length >= 4 are extracted 