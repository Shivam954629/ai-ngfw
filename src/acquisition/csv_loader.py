"""CSV dataset loader for CIC-IDS and UNSW-NB15."""

import pandas as pd
from pathlib import Path
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import DATASETS_DIR


class CSVDataLoader:
    """Load IDS datasets from CSV files."""

    # Common column mappings for different datasets
    CIC_COLUMNS = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_duration",
        "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "label"
    ]

    def __init__(self, datasets_dir: Optional[Path] = None):
        self.datasets_dir = datasets_dir or DATASETS_DIR

    def load_csv(
        self,
        filepath: Path | str,
        max_rows: Optional[int] = None,
        **kwargs
    ) -> pd.DataFrame:
        """Load CSV file with optional row limit."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        df = pd.read_csv(path, nrows=max_rows, low_memory=False, **kwargs)

        # Standardize label column name
        label_cols = [c for c in df.columns if "label" in c.lower() or "attack" in c.lower()]
        if label_cols and "label" not in df.columns:
            df = df.rename(columns={label_cols[0]: "label"})

        return df

    def load_cic_ids(self, filename: str, max_rows: Optional[int] = None) -> pd.DataFrame:
        """Load CIC-IDS2017/2018 format CSV."""
        path = self.datasets_dir / filename
        return self.load_csv(path, max_rows=max_rows)

    def load_unsw_nb15(self, filename: str, max_rows: Optional[int] = None) -> pd.DataFrame:
        """Load UNSW-NB15 format CSV."""
        path = self.datasets_dir / filename
        df = self.load_csv(path, max_rows=max_rows)

        # UNSW-NB15 uses 'attack_cat' and 'label' (0/1)
        if "attack_cat" in df.columns and "label" not in df.columns:
            df["label"] = df.get("label", df.get("attack_cat", "Unknown"))

        return df

    def load_from_directory(
        self,
        pattern: str = "*.csv",
        max_rows_per_file: Optional[int] = 50000,
        max_total_rows: Optional[int] = None,
        exclude: Optional[list] = None,
    ) -> pd.DataFrame:
        """Load and concatenate all matching CSVs from datasets directory."""
        files = list(self.datasets_dir.rglob(pattern))
        if exclude:
            files = [f for f in files if f.name not in exclude]
        if not files:
            return pd.DataFrame()

        dfs = []
        total = 0
        for f in files:
            if max_total_rows and total >= max_total_rows:
                break
            limit = max_rows_per_file
            if max_total_rows:
                limit = min(limit or float("inf"), max_total_rows - total)
            try:
                df = self.load_csv(f, max_rows=int(limit) if limit else None)
                dfs.append(df)
                total += len(df)
            except Exception as e:
                print(f"Warning: Could not load {f}: {e}")

        return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
