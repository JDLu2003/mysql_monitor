# 研究背景

我希望优化 mysql 的 io 行为，特别是 pagecache 的预读方面

# 我希望你编写 bpf 程序用于查看 mysql 应用的 io 行为

你可以使用任何技术去查看相关的 io 行为

我重点在研究 mysql 应用对于 pagecache 相关的读写信息

你首先需要利用 bpf 程序截获相关信息并保存

然后再使用 python 等各种工具去分析数据。

我当前重点关注的是读信息。

# 工具链

你可以使用 bcc、libbpf 等现代工具去截获

你最好使用 kprobe 去 hook

# mysql的行为

mysqld 会 fork 出多个进程去执行不同的任务，你需要截获 mysqld 的所有进程，并关注哪些执行 io 行为的进程和其 io 行为。

# 环境

你现在的环境无法运行 bpf 程序。我会把你的程序放入到正确的环境执行。所以你同时需要告诉我运行的方法

# 简单的例子

以下为一个 bpf 官方的样例，你可以参考学习

但是需要注意的是这个例子关注的是 uprobe，我现在关注的是内核的 mysqld 调用的 io 行为

```
MySQL 查询
要使用 eBPF 跟踪 MySQL 查询，我们可以编写一个使用 bpftrace 的脚本，bpftrace 是一种 eBPF 的高级跟踪语言。以下是一个跟踪 MySQL 中 dispatch_command 函数的脚本，用于记录执行的查询并测量其执行时间：

#!/usr/bin/env bpftrace

// 跟踪 MySQL 中的 dispatch_command 函数
uprobe:/usr/sbin/mysqld:dispatch_command
{
    // 将命令执行的开始时间存储在 map 中
    @start_times[tid] = nsecs;

    // 打印进程 ID 和命令字符串
    printf("MySQL command executed by PID %d: ", pid);

    // dispatch_command 的第三个参数是 SQL 查询字符串
    printf("%s\n", str(arg3));
}

uretprobe:/usr/sbin/mysqld:dispatch_command
{
    // 从 map 中获取开始时间
    $start = @start_times[tid];

    // 计算延迟，以毫秒为单位
    $delta = (nsecs - $start) / 1000000;

    // 打印延迟
    printf("Latency: %u ms\n", $delta);

    // 从 map 中删除条目以避免内存泄漏
    delete(@start_times[tid]);
}
脚本解释
跟踪 dispatch_command 函数：
该脚本在 MySQL 中的 dispatch_command 函数上附加了一个 uprobe。该函数在 MySQL 需要执行 SQL 查询时调用。Uprobe 在内核模式 eBPF 运行时中可能会导致较大的性能开销。在这种情况下，您可以考虑使用用户模式 eBPF 运行时，例如 bpftime。
uprobe 捕获函数执行的开始时间并记录正在执行的 SQL 查询。

计算和记录延迟：

一个相应的 uretprobe 附加到 dispatch_command 函数。uretprobe 在函数返回时触发，允许我们计算查询的总执行时间（延迟）。
延迟以毫秒为单位计算并打印到控制台。

使用 Map 管理状态：

脚本使用一个 BPF map 来存储每个查询的开始时间，并以线程 ID (tid) 作为键。这使我们能够匹配每次查询执行的开始和结束时间。
在计算延迟后，从 map 中删除条目以避免内存泄漏。
运行脚本
要运行此脚本，只需将其保存为文件（例如 trace_mysql.bt），然后使用 bpftrace 执行它：

sudo bpftrace trace_mysql.bt
输出示例
脚本运行后，它将打印 MySQL 执行的每个 SQL 查询的信息，包括进程 ID、查询内容以及延迟时间：

MySQL command executed by PID 1234: SELECT * FROM users WHERE id = 1;
Latency: 15 ms
MySQL command executed by PID 1234: UPDATE users SET name = 'Alice' WHERE id = 2;
Latency: 23 ms
MySQL command executed by PID 1234: INSERT INTO orders (user_id, product_id) VALUES (1, 10);
Latency: 42 ms
这个输出显示了正在执行的 SQL 命令以及每个命令的执行时间，为您提供了关于 MySQL 查询性能的宝贵见解。
```



