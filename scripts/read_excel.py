import os

filepath = os.path.join(os.path.dirname(__file__), '..', 'reports', 'ExportedEstimate.xlsx')

# Check file format
with open(filepath, 'rb') as f:
    header = f.read(16)
    print(f"Header bytes: {header[:8].hex()}")

# Try with olefile first, then pandas
try:
    import olefile
    ole = olefile.OleFileIO(filepath)
    print("OLE streams:", ole.listdir())
    for stream in ole.listdir():
        s = "/".join(stream)
        data = ole.openstream(s).read()
        print(f"  {s}: {len(data)} bytes, starts with: {data[:50]}")
    ole.close()
except ImportError:
    print("olefile not installed, trying pandas...")

# Try pandas as fallback
try:
    import pandas as pd
    dfs = pd.read_excel(filepath, sheet_name=None, engine='xlrd')
    for name, df in dfs.items():
        print(f"\n=== Sheet: {name} ===")
        print(df.to_string())
except Exception as e:
    print(f"pandas/xlrd failed: {e}")
    # Maybe it's an HTML table disguised as .xls
    try:
        import pandas as pd
        dfs = pd.read_html(filepath)
        for i, df in enumerate(dfs):
            print(f"\n=== Table {i} ===")
            print(df.to_string())
    except Exception as e2:
        print(f"HTML parse also failed: {e2}")
