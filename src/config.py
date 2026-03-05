'''
This module contains the configuration settings for the model.
'''
# CONSTANTS

MAX_BYTES = 1 * 1024 * 1024 # 1MB Truncation
SEED = 42 # Reproducibility
MODEL_PATH = "ember_lite_model_2024.txt"
IMPORT_DROPOUT_RATE = 0.30 # Simulating real-world scenario by dropping imports


RAW_COLS_NEEDED = [
    "label", "general", "header", "section",
    "datadirectories", "imports", "exports",
]

FEATURE_COLS = [
    # Top positive correlators (sections — fast)
    "sec_exec_ratio",       # +0.449
    "sec_entropy_std",      # +0.391
    "sec_write_ratio",      # +0.368
    "sec_entropy_max",      # +0.348
    "sec_exec_count",       # +0.317
    "sec_write_count",      # +0.164
    "hdr_sizeof_headers",   # +0.174

    # Top negative correlators
    "datadir_nonempty",     # -0.566  (strongest single feature)
    "imp_available",        # availability flag — tells the model whether to trust imp counts
    "imp_func_count",       # -0.260  (slow, but worth it)
    "imp_dll_count",        # -0.210
    "sec_entropy_min",      # -0.216
    "hdr_sizeof_code",      # -0.188
    "exp_available",        # availability flag for exports
    "exp_count",            # -0.147
    "hdr_major_subsys_ver", # -0.143
    "sec_rawsize_mean",     # -0.129
    "sec_count",            # -0.118
    "sec_read_count",       # -0.114
    "sec_rawsize_max",      # -0.106

    # Lower-signal fast features (still useful for tree splits)
    "sec_entropy_mean",
    "sec_virtsize_mean",
    "gen_size",
    "gen_vsize",
    "gen_has_debug",
    "gen_has_relocations",
    "gen_has_resources",
    "gen_has_signature",
    "gen_has_tls",
    "gen_symbols",
    "hdr_sizeof_init",
    "hdr_sizeof_uninit",
    "hdr_sizeof_heap_commit",
    "hdr_subsystem",
    "hdr_dll_characteristics",
    "hdr_magic",
    "hdr_major_linker_ver",
    "hdr_minor_linker_ver",
    "hdr_major_os_ver",
    "hdr_minor_os_ver",
    "hdr_major_img_ver",
    "hdr_minor_img_ver",
    "hdr_minor_subsys_ver",
    "hdr_file_alignment",
    "hdr_machine",
    "hdr_timestamp",
    "hdr_characteristics",
    "datadir_count",

    # Installer/packer discrimination features — help distinguish
    # NSIS/Inno benign installers from packed malware (both have high entropy)
    "sec_high_entropy_frac", # fraction of sections with entropy > 7.0
    "sec_std_name_frac",     # fraction with standard PE section names
    "imp_has_gui_libs",      # imports user32/gdi32/comctl32/shell32 (GUI app)
    "dd_resource_size",      # RESOURCE data directory size (large = installer)
    "dd_cert_present",       # SECURITY/CERTIFICATE dir present (code-signed)

    # FP-reduction features — from diagnosis of real-world benign scan
    "is_dll",                # hdr_characteristics bit 0x2000 (DLLs ≠ EXEs structurally)
    "has_upx_sections",      # section names contain 'upx' (UPX-packed, often benign tools)
    "has_inno_sections",     # section names contain '.itext' (Inno Setup installer)
    "imp_has_crt",           # imports vcruntime*.dll or api-ms-win-crt-* (C runtime)
]

HDR_OPT_FIELDS = [
    "sizeof_code", "sizeof_headers", "sizeof_initialized_data",
    "sizeof_uninitialized_data", "sizeof_heap_commit", "subsystem",
    "dll_characteristics", "magic", "major_linker_version", "minor_linker_version",
    "major_operating_system_version", "minor_operating_system_version",
    "major_image_version", "minor_image_version",
    "major_subsystem_version", "minor_subsystem_version", "file_alignment",
]
HDR_OPT_ALIASES = [
    "sizeof_code", "sizeof_headers", "sizeof_init", "sizeof_uninit",
    "sizeof_heap_commit", "subsystem", "dll_characteristics", "magic",
    "major_linker_ver", "minor_linker_ver", "major_os_ver", "minor_os_ver",
    "major_img_ver", "minor_img_ver", "major_subsys_ver", "minor_subsys_ver",
    "file_alignment",
]

# EXTRACTOR LOGIC SETS 
# Standard PE section names produced by legitimate compilers
STANDARD_SEC_NAMES = {
    '.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc',
    '.idata', '.edata', '.pdata', '.tls', '.crt', '.debug',
    '.code', '.xdata', '.didat', '.sxdata', '.00cfg',
}

# GUI DLLs used to identify installers and legitimate desktop apps
GUI_DLLS = {
    'user32.dll', 'gdi32.dll', 'comctl32.dll', 
    'shell32.dll', 'comdlg32.dll'
}
# C-Runtime library prefixes (often missing in packed malware)
CRT_PREFIXES = ('vcruntime', 'api-ms-win-crt-')