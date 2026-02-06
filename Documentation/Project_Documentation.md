# EntropyX: PE Feature Extractor for Malware Classification

> **Project Goal:** Build a robust feature extractor for Malware Classification using Random Forest.  
> **Last Updated:** February 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [The Problem & Why Entropy Matters](#2-the-problem--why-entropy-matters)
3. [Development Timeline (Git Commit History)](#3-development-timeline-git-commit-history)
4. [Key Technical Decisions](#4-key-technical-decisions)
5. [Pythonic Implementation Details](#5-pythonic-implementation-details)
6. [Architecture & Code Organization](#6-architecture--code-organization)
7. [Future Improvements](#7-future-improvements)

---

## 1. Project Overview

This project extracts features from Portable Executable (PE) files to train a machine learning model that distinguishes **malware** from **benign** executables. The primary signal is **Shannon Entropy**, which measures randomness in data—encrypted or compressed malware payloads have distinctively high entropy.

### Key Files

| File                         | Purpose                                         |
| ---------------------------- | ----------------------------------------------- |
| `extractor.py`               | Main feature extraction logic                   |
| `generate_custom_malware.sh` | Creates synthetic high-entropy malware samples  |
| `generate_benign.sh`         | Retrieves legitimate Windows system files       |
| `data/malicious/`            | Training samples (custom loaders + SGN encoded) |
| `data/benign/`               | Legitimate Windows executables                  |

---

## 2. The Problem & Why Entropy Matters

### Initial Hypothesis (Flawed)

> "Simply calculate the entropy of the whole file to detect malware."

### Why It Failed

| Issue                 | Explanation                                                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **False Positives**   | Benign installers (e.g., `.msi`, compressed apps) also have high entropy                                                         |
| **Missed Detections** | Malware hides encrypted payloads in _small sections_, while the rest is null padding—averaging the whole file dilutes the signal |
| **Example**           | `custom_loader.exe` showed only **1.4 entropy** at file-level, but **7.13 entropy** in its `.data` section                       |

### The Solution

**Section-Aware Analysis** — Analyze each PE section individually, then summarize with statistics.

---

## 3. Development Timeline (Git Commit History)

This section maps each commit to the problem it solved and the performance/accuracy improvement gained.

### Commit 1: `1fbe40a` — Scripts to generate or retrieve training data

**What:** Created shell scripts to automate dataset generation.  
**Why:** Manual data collection doesn't scale. Needed 600+ samples for balanced training.

---

### Commit 2: `c843e16` — Wrote the function to calculate Shannon entropy

**What:** First implementation of `shanon_helper()`.

```python
# BEFORE (Naive approach)
probabilities = {byte: count / total_bytes for byte, count in counter.items()}
for prob in probabilities.values():
    entropy += prob * math.log2(prob)
entropy = 0.0 - entropy  # Negation at the end
```

**Problem:** Created an intermediate dictionary (`probabilities`) unnecessarily—wasted memory on large files.

---

### Commit 3: `7b2fe64` — Optimized the `shanon_helper` function

**What:** Eliminated the intermediate dictionary and added safety checks.

```python
# AFTER (Optimized)
for count in counter.values():
    prob = count / total_bytes
    entropy -= prob * math.log2(prob)  # Direct subtraction
```

| Improvement         | Before                            | After                        |
| ------------------- | --------------------------------- | ---------------------------- |
| Memory allocation   | Dict of 256 entries               | None (direct iteration)      |
| Empty file handling | ❌ Division by zero crash         | ✅ Returns 0.0 safely        |
| Readability         | Two-step (calculate, then negate) | One-step (subtract directly) |

---

### Commit 4: `1b71e0c` — Updated `extractor.py` and `generate_custom_malware.sh`

**What:** Two critical changes.

#### Change A: Refactored `shanon_helper` to accept binary data (not file path)

```python
# BEFORE: Tightly coupled to file I/O
def shanon_helper(filepath):
    with open(filepath, 'rb') as file:
        file_bytes = file.read()

# AFTER: Pure function, accepts any bytes
def shanon_helper(binary_data):
    counter.update(binary_data)
```

| Improvement     | Impact                                                            |
| --------------- | ----------------------------------------------------------------- |
| **Testability** | Can now unit test with `b'\x00\xff'` without creating files       |
| **Reusability** | Same function works for PE sections, raw buffers, network streams |
| **Performance** | Avoids redundant file opens when PE is already parsed             |

#### Change B: Fixed the "Hex Trap" in malware generation

**The Bug:** Generating payloads as hex strings (`A-F0-9`) limited entropy to **~4.0 bits**.

> Hex uses only 16 characters (4 bits of entropy max), not 256 possible byte values (8 bits).

```bash
# BEFORE (Limited entropy)
PAYLOAD_DATA=$(head /dev/urandom | tr -dc A-F0-9 | head -c $PAYLOAD_SIZE)
const char encrypted_payload[] = "$PAYLOAD_DATA";  # Stored as ASCII string

# AFTER (True randomness)
PAYLOAD_ARRAY=$(head -c $PAYLOAD_SIZE /dev/urandom | od -An -v -t x1 | ...)
unsigned char encrypted_payload[] = { $PAYLOAD_ARRAY };  # Stored as raw bytes
```

| Metric                  | Before (Hex String)         | After (Raw Bytes)                    |
| ----------------------- | --------------------------- | ------------------------------------ |
| Max theoretical entropy | 4.0 bits                    | 8.0 bits                             |
| Actual measured entropy | ~3.8 bits                   | ~7.99 bits                           |
| Realism                 | ❌ No real malware uses hex | ✅ Mimics AES/RC4 encrypted payloads |

---

### Commit 5: `a1dd06c` — Orchestrator v1 and `get_structural_features`

**What:** Introduced the Orchestrator pattern and added structural features.

#### New Features Extracted

| Feature                      | Why It Matters                                           |
| ---------------------------- | -------------------------------------------------------- |
| `num_sections`               | Packed malware often has unusual section counts          |
| `virtual_size_ratio`         | Ratio > 1.0 indicates runtime unpacking (malware signal) |
| `raw_size` vs `virtual_size` | Discrepancy reveals hidden payloads                      |

#### Architectural Change: Orchestrator Pattern

```python
def extract_all_features(filepath) -> dict:  # Orchestrator
    pe = pefile.PE(filepath)
    features = {}
    features.update(get_entropy_features(pe))      # Worker 1
    features.update(get_structural_features(pe))   # Worker 2
    pe.close()
    return features
```

| Benefit                   | Explanation                                                |
| ------------------------- | ---------------------------------------------------------- |
| **Extensibility**         | Add `get_import_features()` without touching entropy logic |
| **Single Responsibility** | Each worker does one thing well                            |
| **Resource Safety**       | `pe.close()` in one place (now in `finally` block)         |

---

## 4. Key Technical Decisions

### Decision 1: VirtualSize vs. RawSize for Entropy Calculation

**Observation:** Malware often has `VirtualSize > SizeOfRawData` because it unpacks at runtime.

**Problem:** `section.get_data()` returns raw bytes padded with nulls, diluting entropy.

**Solution:**

```python
section_data_trimmed = section.get_data()[:section.Misc_VirtualSize]
```

| Scenario                                   | Without Trimming | With Trimming |
| ------------------------------------------ | ---------------- | ------------- |
| 10KB encrypted payload + 90KB null padding | ~0.8 entropy     | ~7.9 entropy  |

---

### Decision 2: Statistical Aggregation for Variable-Length Data

**Problem:** ML models need fixed-length input vectors, but PE files have 3-10+ sections.

**Solution:** Summarize with statistical moments:

```python
entropy_summary = {
    'avg_entropy': mean(entropies),    # Overall complexity
    'max_entropy': max(entropies),     # THE KEY SIGNAL (encrypted section)
    'min_entropy': min(entropies),     # Null-padded sections
    'std_entropy': np.std(entropies)   # Variance between sections
}
```

**Why `std_entropy` is crucial:**  
Benign files have _consistent_ entropy across sections. Malware has _spikes_ (encrypted payload vs. empty padding). Standard deviation captures this variance.

---

### Decision 3: Error Handling at Orchestrator Level

**Pattern:** Workers assume valid input; Orchestrator handles exceptions.

#### ⚠️ Bug Discovered: UnboundLocalError in `finally` Block

**The Mistake:**

```python
def extract_all_features(filepath) -> dict:
    try:
        pe = pefile.PE(filepath)  # If this fails, pe is never assigned
        # ... call workers ...
    except pefile.PEFormatError as e:
        print(f"Error processing {filepath}: {e}")
        return None
    finally:
        pe.close()  # ❌ CRASH: UnboundLocalError if file doesn't exist
```

**What Happened:**  
When a `FileNotFoundError` occurred (wrong file path), the `pe = pefile.PE(filepath)` line threw an exception _before_ `pe` was assigned. The `finally` block still executed, but `pe` didn't exist—causing a _second_ error that masked the real problem.

**The Fix:**

```python
def extract_all_features(filepath) -> dict:
    pe = None  # ✅ Initialize before try block
    try:
        pe = pefile.PE(filepath)
        # ... call workers ...
    except pefile.PEFormatError as e:
        print(f"Error processing {filepath}: {e}")
        return None
    finally:
        if pe is not None:  # ✅ Guard before closing
            pe.close()
```

| Issue        | Before                               | After                            |
| ------------ | ------------------------------------ | -------------------------------- |
| Missing file | `UnboundLocalError` masks real error | Shows actual `FileNotFoundError` |
| Invalid PE   | `UnboundLocalError`                  | Graceful `None` return           |
| Valid PE     | Works                                | Works                            |

**Lesson Learned:**  
Always initialize resources to `None` before a `try` block when using `finally` for cleanup. This pattern is called **"Initialize-Try-Finally"** and prevents cascading errors.

| Benefit                     | Impact                                             |
| --------------------------- | -------------------------------------------------- |
| **Cleaner workers**         | No redundant try/except in every function          |
| **Consistent error format** | All errors logged the same way                     |
| **Memory safety**           | `finally` ensures handles are closed even on crash |
| **Error transparency**      | Real exceptions aren't masked by cleanup failures  |

---

## 5. Pythonic Implementation Details

### 5.1 Counter.update() vs. Manual Loop

```python
# ❌ WRONG: Treats entire bytes object as one key
counter[file_bytes] += 1  # Result: Counter({b'...': 1})

# ❌ SLOW: Correct but inefficient
for byte in file_bytes:
    counter[byte] += 1

# ✅ OPTIMAL: C-optimized iteration
counter.update(file_bytes)  # ~10x faster for large files
```

**Why `update()` is faster:** Implemented in CPython's C internals, avoiding Python's interpreter overhead per byte.

---

### 5.2 Binary Data Representation in Python

**Misconception:** Expecting `b'\x7f\x45\x4c\x46'` when printing bytes.

**Reality:** Python displays printable ASCII: `b'\x7fELF'`

**Insight:** Internally, Python treats bytes as integers 0-255. To see them:

```python
>>> list(b'ELF')
[69, 76, 70]
```

This is exactly what Shannon entropy math uses—256 possible byte values.

---

## 6. Architecture & Code Organization

```
extractor.py
├── shanon_helper(binary_data)      # Pure function: bytes → entropy float
├── get_entropy_features(pe)        # Worker: PE → entropy dict
├── get_structural_features(pe)     # Worker: PE → structure dict
└── extract_all_features(filepath)  # Orchestrator: path → final feature dict
```

### Design Principles Applied

| Principle                 | Implementation                                   |
| ------------------------- | ------------------------------------------------ |
| **Single Responsibility** | Each function does exactly one thing             |
| **Dependency Injection**  | Workers receive `pe` object, don't open files    |
| **Fail Fast**             | Orchestrator validates PE before calling workers |
| **Resource Management**   | `try/finally` ensures `pe.close()` always runs   |

---

## 7. Future Improvements

- [ ] **Import Address Table (IAT) Analysis** — Detect suspicious API calls (`VirtualAlloc`, `WriteProcessMemory`)
- [ ] **Section Name Analysis** — Flag unusual names like `UPX0`, `.enigma`
- [ ] **String Extraction** — Find hardcoded C2 URLs or registry keys
- [ ] **YARA Rule Integration** — Cross-reference with known malware signatures
- [ ] **Batch Processing Pipeline** — Parallel extraction with `multiprocessing`

---

## Appendix: Quick Reference

### Shannon Entropy Formula

$$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$

Where $p(x_i)$ is the probability of byte value $i$ appearing in the data.

### Entropy Interpretation

| Entropy Range | Meaning                      | Example                 |
| ------------- | ---------------------------- | ----------------------- |
| 0.0 - 1.0     | Highly structured/repetitive | Null-padded sections    |
| 4.0 - 5.0     | Plain text / code            | `.text` section         |
| 7.0 - 8.0     | Encrypted / compressed       | AES payload, packed UPX |

---

_Document maintained as part of the EntropyX malware classification project._
