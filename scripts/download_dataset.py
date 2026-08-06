"""Dataset Downloader Script for Atomic-EVTX.

Downloads all 12 attack categories for the `attacks_by_category_atomic_and_tools_removed` variant
from the official repository into dataset/atomic-evtx-extracted/attacks_by_category_atomic_and_tools_removed/.

Categories:
1. collection
2. command-and-control
3. credential-access
4. defense-evasion
5. discovery
6. execution
7. exfiltration
8. impact
9. initial-access
10. lateral-movement
11. persistence
12. privilege-escalation
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

DATASET_ROOT = Path(__file__).resolve().parent.parent / "dataset" / "atomic-evtx-extracted" / "attacks_by_category_atomic_and_tools_removed"

CATEGORIES = [
    "collection",
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "initial-access",
    "lateral-movement",
    "persistence",
    "privilege-escalation"
]

REPO_URL = "https://github.com/Security-Datasets/Atomic-EVTX.git"

def check_existing_categories():
    """Report status of currently present dataset categories."""
    DATASET_ROOT.mkdir(parents=True, exist_ok=True)
    present = []
    missing = []
    for cat in CATEGORIES:
        cat_dir = DATASET_ROOT / cat
        if cat_dir.exists() and any(cat_dir.iterdir()):
            count = len(list(cat_dir.iterdir()))
            present.append((cat, count))
        else:
            missing.append(cat)
    return present, missing

def main():
    print("=== Atomic-EVTX Dataset Verification & Downloader ===")
    present, missing = check_existing_categories()
    
    print(f"\nCurrently present categories ({len(present)}/12):")
    for cat, count in present:
        print(f"  [OK] {cat}: {count} scenarios")
        
    if not missing:
        print("\nAll 12 categories are present and verified!")
        return

    print(f"\nMissing categories to download ({len(missing)}/12): {', '.join(missing)}")
    temp_clone_dir = Path(__file__).resolve().parent.parent / "temp_atomic_evtx_clone"
    
    try:
        print(f"\nCloning repository from {REPO_URL} (this may take a few minutes)...")
        subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, str(temp_clone_dir)],
            check=True
        )
        
        source_base = temp_clone_dir / "attacks_by_category_atomic_and_tools_removed"
        if not source_base.exists():
            # Try alternate path if layout differs
            source_base = temp_clone_dir
            
        for cat in missing:
            src_cat = source_base / cat
            dest_cat = DATASET_ROOT / cat
            if src_cat.exists():
                print(f"Copying category: {cat}...")
                if dest_cat.exists():
                    shutil.rmtree(dest_cat)
                shutil.copytree(src_cat, dest_cat)
                print(f"  [DONE] {cat} copied successfully.")
            else:
                print(f"  [WARNING] Category {cat} not found in repo clone.")
                
    except Exception as e:
        print(f"Download/Copy failed: {e}")
    finally:
        if temp_clone_dir.exists():
            print("Cleaning up temporary clone folder...")
            shutil.rmtree(temp_clone_dir, ignore_errors=True)
            
    print("\nDataset status update:")
    present, missing = check_existing_categories()
    print(f"Present categories: {len(present)}/12")

if __name__ == "__main__":
    main()
