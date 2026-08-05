import os
import subprocess
import sys

def sanitize_path(rel_path):
    # Windows forbidden characters in file/directory names: : ? * < > " |
    # Note: rel_path uses forward slashes / for git paths
    parts = rel_path.split('/')
    sanitized_parts = []
    for p in parts:
        # Replace invalid windows chars in each component
        for char in [':', '?', '*', '<', '>', '"', '|']:
            p = p.replace(char, '_')
        # Also trim trailing spaces or dots which Windows hates
        p = p.strip()
        if not p:
            p = "_"
        sanitized_parts.append(p)
    return os.path.join(*sanitized_parts)

def extract_git_repo(repo_dir, target_dir):
    print(f"Listing git objects from {repo_dir}...")
    cmd = ["git", "ls-tree", "-r", "HEAD"]
    res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if res.returncode != 0:
        print("Error listing git tree:", res.stderr)
        return False
    
    lines = res.stdout.strip().split('\n')
    print(f"Found {len(lines)} files in repository.")
    
    count = 0
    err_count = 0
    for line in lines:
        if not line.strip():
            continue
        # Format: <mode> <type> <hash>\t<path>
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        meta, git_path = parts
        meta_parts = meta.split()
        if len(meta_parts) < 3:
            continue
        obj_type = meta_parts[1]
        obj_hash = meta_parts[2]
        
        if obj_type == "blob":
            dest_rel_path = sanitize_path(git_path)
            dest_full_path = os.path.join(target_dir, dest_rel_path)
            os.makedirs(os.path.dirname(dest_full_path), exist_ok=True)
            
            # Fetch content using git cat-file -p <hash>
            cat_cmd = ["git", "cat-file", "-p", obj_hash]
            cat_res = subprocess.run(cat_cmd, cwd=repo_dir, capture_output=True)
            if cat_res.returncode == 0:
                with open(dest_full_path, 'wb') as f:
                    f.write(cat_res.stdout)
                count += 1
                if count % 500 == 0:
                    print(f"Extracted {count}/{len(lines)} files...")
            else:
                print(f"Failed to extract {git_path} ({obj_hash})")
                err_count += 1

    print(f"Extraction complete! Extracted {count} files successfully ({err_count} errors).")
    return True

if __name__ == '__main__':
    repo_dir = r"c:\Users\hp\Desktop\Capstone\dataset\atomic-evtx"
    target_dir = r"c:\Users\hp\Desktop\Capstone\dataset\atomic-evtx-extracted"
    extract_git_repo(repo_dir, target_dir)
