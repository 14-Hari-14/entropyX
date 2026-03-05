import numpy as np
import hashlib
from config import HDR_OPT_FIELDS, HDR_OPT_ALIASES, STANDARD_SEC_NAMES, GUI_DLLS, CRT_PREFIXES

def safe_get(d, *keys, default=0):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d if d is not None else default

def stable_hash_bin(value, bins):
    digest = hashlib.blake2b(str(value).encode("utf-8"), digest_size=8).digest()
    idx = int.from_bytes(digest, "little") % bins
    sign = -1.0 if (digest[0] & 1) else 1.0
    return idx, sign

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

    # -- Rich Header --
    rich_obj = row.get("rich_header", row.get("richheader", row.get("rich", [])))
    rich_values = []
    if isinstance(rich_obj, dict):
        rich_values = rich_obj.get("values", rich_obj.get("raw", []))
    elif isinstance(rich_obj, list):
        rich_values = rich_obj

    rich_bins = 8
    for i in range(rich_bins):
        out[f"rich_hash_{i}"] = 0.0
    out["rich_num_pairs"] = 0

    if isinstance(rich_values, list) and len(rich_values) >= 2:
        n_pairs = len(rich_values) // 2
        out["rich_num_pairs"] = n_pairs
        for i in range(0, n_pairs * 2, 2):
            compid = rich_values[i]
            count = rich_values[i + 1]
            if not isinstance(count, (int, float)):
                continue
            idx, sign = stable_hash_bin(compid, rich_bins)
            out[f"rich_hash_{idx}"] += sign * float(count)

    # -- Authenticode --
    auth = row.get("authenticode", row.get("signature", row.get("signing", {})))
    out["auth_num_certs"] = 0
    out["auth_self_signed"] = 0
    out["auth_parse_error"] = 0
    out["auth_chain_depth"] = 0
    out["auth_sign_time_delta_abs"] = 0
    out["auth_no_countersigner"] = 0

    if isinstance(auth, dict):
        out["auth_num_certs"] = safe_get(auth, "num_certs", default=safe_get(auth, "certificate_count", default=0))
        out["auth_self_signed"] = int(bool(safe_get(auth, "self_signed", default=0)))
        out["auth_parse_error"] = int(bool(safe_get(auth, "parse_error", default=0)))
        out["auth_chain_depth"] = safe_get(auth, "chain_max_depth", default=safe_get(auth, "chain_depth", default=0))
        out["auth_no_countersigner"] = int(bool(safe_get(auth, "no_countersigner", default=0)))
        sign_delta = safe_get(auth, "signing_time_diff", default=safe_get(auth, "sign_time_delta", default=0))
        if isinstance(sign_delta, (int, float)):
            out["auth_sign_time_delta_abs"] = abs(sign_delta)

    # -- PE Parse Warnings --
    warnings_obj = row.get("pe_warnings", row.get("pefile_warnings", row.get("pefilewarnings", row.get("warnings", []))))
    if isinstance(warnings_obj, str):
        warnings_list = [warnings_obj]
    elif isinstance(warnings_obj, dict):
        warnings_list = [f"{k}:{v}" for k, v in warnings_obj.items()]
    elif isinstance(warnings_obj, list):
        warnings_list = [str(w) for w in warnings_obj]
    else:
        warnings_list = []

    warnings_text = " ".join(w.lower() for w in warnings_list)
    out["pe_warn_count"] = len(warnings_list)
    out["pe_warn_checksum"] = int("checksum" in warnings_text)
    out["pe_warn_section"] = int("section" in warnings_text)
    out["pe_warn_import"] = int("import" in warnings_text)
    out["pe_warn_export"] = int("export" in warnings_text)
    out["pe_warn_overlay"] = int("overlay" in warnings_text)

    # -- Overlay --
    overlay = row.get("overlay", safe_get(sec, "overlay", default={}))
    out["overlay_size"] = 0
    out["overlay_size_ratio"] = 0
    out["overlay_entropy"] = 0
    out["overlay_present"] = 0

    if isinstance(overlay, dict):
        overlay_size = safe_get(overlay, "size", default=0)
        overlay_ratio = safe_get(overlay, "size_ratio", default=0)
        overlay_entropy = safe_get(overlay, "entropy", default=0)
        out["overlay_size"] = overlay_size
        out["overlay_size_ratio"] = overlay_ratio
        out["overlay_entropy"] = overlay_entropy
        out["overlay_present"] = int(bool(overlay_size))

    return out