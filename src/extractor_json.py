import numpy as np
from config import HDR_OPT_FIELDS, HDR_OPT_ALIASES, STANDARD_SEC_NAMES, GUI_DLLS, CRT_PREFIXES

def safe_get(d, *keys, default=0):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d if d is not None else default

def extract_row_features(row):
    """Extract all flat features from one JSONL row. Returns a dict of scalars."""
    out = {}

    # -- General --
    g = row.get("general", {})
    for field in ["vsize", "size", "has_debug", "has_relocations",
                  "has_resources", "has_signature", "has_tls", "symbols"]:
        out[f"gen_{field}"] = safe_get(g, field)

    # -- Header (file + optional) --
    h = row.get("header", {})
    for field in ["machine", "timestamp", "characteristics"]:
        out[f"hdr_{field}"] = safe_get(h, "file", field)
    for field, alias in zip(HDR_OPT_FIELDS, HDR_OPT_ALIASES):
        out[f"hdr_{alias}"] = safe_get(h, "optional", field)

    # DLL flag — extracted from FILE_HEADER characteristics bit 0x2000
    chars = safe_get(h, "file", "characteristics")
    out["is_dll"] = int(bool(chars & 0x2000)) if isinstance(chars, (int, float)) else 0

    # -- Sections --
    sec = row.get("section", {})
    sections = sec.get("sections", []) if isinstance(sec, dict) else []

    n = len(sections)
    if n == 0:
        out["sec_count"] = 0
        for k in ["sec_entropy_mean", "sec_entropy_max", "sec_entropy_min",
                   "sec_entropy_std", "sec_rawsize_mean", "sec_rawsize_max",
                   "sec_virtsize_mean", "sec_exec_count", "sec_write_count",
                   "sec_read_count", "sec_exec_ratio", "sec_write_ratio",
                   "sec_high_entropy_frac", "sec_std_name_frac"]:
            out[k] = 0
        out["has_upx_sections"] = 0
        out["has_inno_sections"] = 0
    else:
        ent   = [s.get("entropy", 0) for s in sections]
        rsz   = [s.get("size", 0)    for s in sections]
        vsz   = [s.get("vsize", 0)   for s in sections]
        props = [s.get("props", [])   for s in sections]
        names = [s.get("name", "").lower().strip() for s in sections]
        ex = sum(1 for p in props if "MEM_EXECUTE" in p)
        wr = sum(1 for p in props if "MEM_WRITE"   in p)
        rd = sum(1 for p in props if "MEM_READ"    in p)

        # Packer/installer section name detection
        out["has_upx_sections"]  = int(any("upx" in nm for nm in names))
        out["has_inno_sections"] = int(any(nm == ".itext" for nm in names))

        out.update({
            "sec_count": n,
            "sec_entropy_mean":  np.mean(ent), "sec_entropy_max": np.max(ent),
            "sec_entropy_min":   np.min(ent),  "sec_entropy_std": np.std(ent),
            "sec_rawsize_mean":  np.mean(rsz), "sec_rawsize_max": np.max(rsz),
            "sec_virtsize_mean": np.mean(vsz),
            "sec_exec_count": ex, "sec_write_count": wr, "sec_read_count": rd,
            "sec_exec_ratio": ex / n, "sec_write_ratio": wr / n,
            "sec_high_entropy_frac": sum(1 for e in ent if e > 7.0) / n,
            "sec_std_name_frac": sum(1 for nm in names if nm in STANDARD_SEC_NAMES) / n,
        })

    # -- Data Directories --
    dd = row.get("datadirectories", [])
    if isinstance(dd, list):
        out["datadir_count"]    = len(dd)
        out["datadir_nonempty"] = sum(1 for d in dd if isinstance(d, dict) and d.get("size", 0) > 0)
        # Index 2 = RESOURCE, Index 4 = SECURITY/CERTIFICATE (standard PE order)
        out["dd_resource_size"] = dd[2].get("size", 0) if len(dd) > 2 and isinstance(dd[2], dict) else 0
        out["dd_cert_present"]  = int((dd[4].get("size", 0) if len(dd) > 4 and isinstance(dd[4], dict) else 0) > 0)
    elif isinstance(dd, dict):
        out["datadir_count"]    = len(dd)
        out["datadir_nonempty"] = sum(1 for d in dd.values() if isinstance(d, dict) and d.get("size", 0) > 0)
        out["dd_resource_size"] = 0
        out["dd_cert_present"]  = 0
    else:
        out["datadir_count"] = out["datadir_nonempty"] = 0
        out["dd_resource_size"] = 0
        out["dd_cert_present"]  = 0

    # -- Imports (with availability flag for covariate shift protection) --
    imp = row.get("imports", {})
    if isinstance(imp, dict) and len(imp) > 0:
        out["imp_available"]  = 1
        out["imp_dll_count"]  = len(imp)
        out["imp_func_count"] = sum(len(v) if isinstance(v, list) else 0 for v in imp.values())
        dll_lower = {k.lower() for k in imp.keys()}
        out["imp_has_gui_libs"] = int(bool(dll_lower & GUI_DLLS))
        out["imp_has_crt"]      = int(any(d.startswith(CRT_PREFIXES) for d in dll_lower))
    else:
        out["imp_available"] = out["imp_dll_count"] = out["imp_func_count"] = 0
        out["imp_has_gui_libs"] = 0
        out["imp_has_crt"]      = 0

    # -- Exports (with availability flag) --
    exp = row.get("exports", [])
    cnt = len(exp) if isinstance(exp, (list, dict)) else 0
    out["exp_count"]     = cnt
    out["exp_available"] = int(cnt > 0)

    return out