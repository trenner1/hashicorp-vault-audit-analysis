# Performance Benchmark: Python vs Rust

## Test Environment
- **Machine**: Apple Silicon (M-series)
- **Log File**: `vault_audit.2025-10-07.log`
- **File Size**: 15 GB
- **Total Lines**: 3,986,972
- **KV Operations**: 719,978
- **Unique Paths**: 1,365

## Results

### Python 3.13
**Tool**: `bin/vault_audit_kv_analyzer.py`

```
Total Time:      40.11 seconds
CPU Time:        36.93s user + 2.25s system
CPU Usage:       97%
Throughput:      99,400 lines/second
```

### Rust 1.90
**Tool**: `vault-audit-kv-analyzer-rs/target/release/vault-audit-kv-analyzer-rs`

```
Total Time:      8.88 seconds  ⚡
CPU Time:        7.17s user + 1.63s system  
CPU Usage:       99%
Throughput:      448,800 lines/second  🚀
```

## Performance Comparison

| Metric | Python | Rust | Improvement |
|--------|--------|------|-------------|
| **Total Time** | 40.11s | 8.88s | **4.52x faster** |
| **CPU Time (user)** | 36.93s | 7.17s | **5.15x faster** |
| **Throughput** | 99.4K lines/s | 448.8K lines/s | **4.51x higher** |
| **Time Saved** | - | 31.23s | **77.9% reduction** |

## Winner: Rust 🦀

The Rust implementation is **4.5x faster** than Python on this real-world 15GB audit log.

## Output Verification

Both versions produced identical results:
- ✅ Same number of lines parsed (3,986,972)
- ✅ Same KV operations found (719,978)
- ✅ Same paths analyzed (1,365)
- ✅ Same CSV structure and data

## Why Rust is Faster

1. **Zero-cost abstractions**: No runtime overhead for features like iterators
2. **No GC pauses**: Manual memory management without garbage collection
3. **Compiled to native code**: Direct machine code vs interpreted bytecode
4. **Efficient JSON parsing**: `serde_json` is highly optimized
5. **Better CPU cache utilization**: Tight memory layout and predictable access patterns

## When to Use Each Version

### Use Python (`bin/vault_audit_kv_analyzer.py`)
- ✅ Quick ad-hoc analysis
- ✅ Need to modify/debug the script
- ✅ Logs are small (<1GB)
- ✅ Already have Python environment

### Use Rust (`vault-audit-kv-analyzer-rs`)
- ✅ Processing very large logs (>5GB)
- ✅ Running repeatedly/in automation
- ✅ Need maximum performance
- ✅ Want a single compiled binary

## Real-World Impact

For a 15GB log file:
- **Python**: 40 seconds
- **Rust**: 9 seconds
- **Time saved**: 31 seconds per run

If you analyze logs daily for a month:
- **Time saved**: 15.6 minutes/month
- **Annualized**: 3.1 hours/year

For teams analyzing multiple large logs daily, Rust version pays for itself quickly!

## Conclusion

The Rust implementation proves that rewriting performance-critical tools in Rust can yield **significant real-world benefits** while maintaining **identical functionality** and **output format compatibility**.

Just for fun turned into a legit performance win! 🎉
