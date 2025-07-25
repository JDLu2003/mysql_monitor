# MySQL Page Cache Readahead Monitor

This project provides a tool to monitor the page cache readahead I/O behavior of MySQL (and its variants like MariaDB) on Linux. It uses eBPF (Extended Berkeley Packet Filter) to trace kernel-level file I/O operations specifically related to `mysqld` processes, providing insights into how MySQL utilizes the kernel's readahead mechanism.

The collected data can help database administrators and system engineers to:
- Understand which database files (tables, indexes, etc.) are triggering readahead operations.
- Analyze the size and frequency of readahead events.
- Identify potential I/O inefficiencies.
- Tune MySQL or kernel parameters for better I/O performance.

## How it Works

The tool consists of a single Python script that leverages the **BCC (BPF Compiler Collection)** framework.

1.  **eBPF Program**: A small C program is embedded within the Python script. This program is compiled at runtime by BCC and loaded into the Linux kernel.
2.  **Kprobe**: The eBPF program attaches a **kprobe** to the `__do_page_cache_readahead` function in the kernel. This function is a core part of the filesystem layer responsible for initiating file content pre-fetching into the page cache.
3.  **Filtering**: To minimize overhead, the eBPF code filters events directly in the kernel, only capturing those initiated by processes named `mysqld`.
4.  **Data Collection**: When a `mysqld` process triggers a readahead operation, the kprobe fires, and the eBPF program collects relevant data (PID, filename, number of pages, offset).
5.  **Perf Buffer**: The collected data is sent from kernel space to user space via a high-performance perf buffer.
6.  **User Space Processing**: The Python script reads the data from the perf buffer, formats it, and either prints it to the console or saves it to a CSV file for persistent storage and later analysis.

## Requirements

- **Operating System**: Linux (kernel version 4.1 or newer recommended).
- **Kernel Headers**: Required for BCC to compile the eBPF program.
- **BCC (BPF Compiler Collection)**: The toolchain used to build and run the eBPF program.
- **Python 3**: The user-space script is written in Python 3.

## Installation

1.  **Clone the repository or download the script.**

2.  **Install Kernel Headers**:
    The command depends on your Linux distribution.

    *   For Debian/Ubuntu:
        ```bash
        sudo apt-get update
        sudo apt-get install -y linux-headers-$(uname -r)
        ```
    *   For RHEL/CentOS/Fedora:
        ```bash
        sudo yum install -y kernel-devel-$(uname -r)
        ```

3.  **Install BCC**:
    Follow the official installation guide at [BCC INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

    *   For Debian/Ubuntu:
        ```bash
        sudo apt-get install -y bpfcc-tools
        ```
    *   For RHEL/CentOS/Fedora:
        ```bash
        sudo yum install -y bcc-tools
        ```

## Usage

The script must be run with `root` privileges (`sudo`) to allow loading the eBPF program into the kernel.

**1. Print to Console**

To monitor events in real-time and print them to the standard output:
```bash
sudo python3 mysql_readahead_monitor.py
```

**2. Save to CSV File**

To capture events and save them to a CSV file for later analysis, use the `-o` or `--output` flag:
```bash
sudo python3 mysql_readahead_monitor.py --output /path/to/mysql_readahead_log.csv
```
The script will run until you stop it with `Ctrl+C`.

### Command-line Arguments

- `-h`, `--help`: Show the help message and exit.
- `-o FILE`, `--output FILE`: Path to a CSV file to save the output. If not provided, prints to standard output.

## Output Format

Whether printed to the console or saved in a CSV file, the output contains the following columns:

| Column      | Type    | Description                                                                 |
|-------------|---------|-----------------------------------------------------------------------------|
| `Timestamp` | String  | The timestamp of the event in `YYYY-MM-DD HH:MM:SS` format.                 |
| `PID`       | Integer | The Process ID of the `mysqld` worker that triggered the readahead.         |
| `Command`   | String  | The name of the command (e.g., `mysqld`).                                   |
| `File`      | String  | The name of the file being read (e.g., `ibdata1`, `my_table.ibd`).          |
| `Pages`     | Integer | The number of memory pages the kernel is pre-fetching. (1 page = 4KB typ.)  |
| `Offset`    | Integer | The starting offset within the file where the readahead begins (in pages).  |

## Data Analysis Example

Once you have collected data in a CSV file (`mysql_readahead_log.csv`), you can analyze it using tools like Python with the `pandas` library.

Here is a simple example of how to load and analyze the data in a separate Python script or a Jupyter Notebook:

```python
import pandas as pd
import matplotlib.pyplot as plt

# Load the collected data
try:
    df = pd.read_csv('mysql_readahead_log.csv')
except FileNotFoundError:
    print("Error: Log file not found.")
    exit()

# --- Analysis Examples ---

# 1. Show basic information
print("Data Overview:")
print(df.info())
print("\nTop 5 most frequently read files:")
print(df['File'].value_counts().head(5))

# 2. Calculate total readahead size per file (in KB)
# Assuming page size is 4 KB
df['ReadaheadKB'] = df['Pages'] * 4
total_readahead_kb = df.groupby('File')['ReadaheadKB'].sum().sort_values(ascending=False)
print("\nTotal readahead volume per file (KB):")
print(total_readahead_kb.head(10))

# 3. Plot the top 5 files by readahead frequency
plt.figure(figsize=(10, 6))
df['File'].value_counts().head(5).plot(kind='bar', title='Top 5 Files by Readahead Frequency')
plt.ylabel('Number of Readahead Events')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
```

## License

This project is licensed under the Apache License, Version 2.0.

---

## Alternative: Using `bpftrace` for Quick Analysis

For users who prefer a higher-level, scripting-based approach, this project also includes a `bpftrace` script (`mysql_io_trace.bt`) that provides a comprehensive view of MySQL's I/O activity.

### Advantages of `bpftrace`

- **Simplicity**: A single script file contains all the logic.
- **Flexibility**: Easy to modify on the fly for different tracing needs.
- **Broad View**: It hooks `vfs_read` and `vfs_write`, capturing **all** file I/O (not just readahead), which gives a more complete picture of disk access patterns.

### How to Use `mysql_io_trace.bt`

This script traces VFS read and write operations initiated by `mysqld` processes.

**Requirements**:
- `bpftrace` installed on your Linux system.
- Root privileges to run.

**1. Run and Print to Console**

Execute the script directly. It will print a CSV header and then stream live I/O events to your terminal. Press `Ctrl+C` to stop.

```bash
sudo bpftrace mysql_io_trace.bt
```

**2. Save Output to a CSV File**

You can easily redirect the output to a file for later analysis:

```bash
sudo bpftrace mysql_io_trace.bt > mysql_vfs_io.csv
```

### `bpftrace` Output Format

The output is formatted as a clean, comma-separated list with the following columns:

| Column      | Description                                      |
|-------------|--------------------------------------------------|
| `Timestamp` | The timestamp of the I/O event.                  |
| `PID`       | The Process ID of the `mysqld` worker.           |
| `Command`   | The process name (`mysqld`).                     |
| `Operation` | The type of I/O: `read` or `write`.              |
| `File`      | The name of the file being accessed.             |
| `Size(Bytes)`| The size of the read/write request in bytes.     |
