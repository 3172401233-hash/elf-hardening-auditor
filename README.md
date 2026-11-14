# elf-hardening-auditor

面向发布门禁的 ELF 加固检查库。**只读取二进制元数据**：不反汇编、不执行目标程序。
目前支持 32/64 位小端 ELF，其他格式（如大端）返回 `unsupported`。

## 检查项与证据

每份 ELF 输出六项检查，每个结论都附带元数据证据（segment flags、section、
dynamic tag 或符号名称），不凭单一节名下结论：

| 检查 | 判定依据 |
| --- | --- |
| `nx` | `PT_GNU_STACK` 的 `PF_X` 标志（缺失时报 `unknown`） |
| `pie` | `e_type` 为 `ET_DYN`/`ET_EXEC`，结合 `PT_INTERP` |
| `relro` | `PT_GNU_RELRO` 段 + `DT_BIND_NOW` / `DF_BIND_NOW` / `DF_1_NOW`（full/partial/none） |
| `stack_protector` | `.dynsym`/`.symtab` 中的 `__stack_chk_fail` / `__stack_chk_guard` 符号 |
| `fortify` | 符号表中的 `__*_chk` 符号（如 `__printf_chk`） |
| `wx` | 是否存在同时带 `PF_W` 和 `PF_X` 的 `PT_LOAD` 段 |

## 用法

```bash
python -m elf_audit /path/to/binary          # 格式化 JSON
python -m elf_audit a.so b.so --compact      # 单行 JSON
```

```python
from elf_audit import audit_file
result = audit_file("/bin/ls")
print(result["checks"]["relro"])  # {'status': 'full', 'evidence': [...]}
```

顶层 `status` 为 `ok` / `unsupported` / `error`。损坏输入返回结构化错误，
`error.code` 取值包括：`bad_header`、`overlapping_segments`、
`dynamic_table_out_of_bounds`、`string_table_truncated`、
`section_out_of_bounds`。所有读取均做边界检查，不会越界访问。

## 测试

```bash
python -m unittest
```

测试用代码生成多种安全/危险配置的最小 ELF（32/64 位），并覆盖损坏 header、
重叠 segment、越界动态表、截断字符串表和逐字节截断模糊测试。

## 注意

这些标志只代表**构建配置**（编译/链接选项），不等于程序不存在漏洞。
即使全部检查通过，程序仍可能存在内存安全或逻辑漏洞；反之，个别检查未过
也不代表必然可被利用。请将其作为发布门禁的一个信号，而非安全保证。
