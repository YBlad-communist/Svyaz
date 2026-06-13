import os
import re

templates_dir = r'C:\Users\User\Desktop\Svyaz.git\templates'
files_fixed = 0

for fname in os.listdir(templates_dir):
    if not fname.endswith('.html'):
        continue
    fpath = os.path.join(templates_dir, fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
    # Replace bare <script> (line starting with <script> and no nonce or src)
    new_content = re.sub(
        r'<script(?!\s+(nonce|src))>',
        '<script nonce="{{ csp_nonce() }}">',
        content
    )
    if new_content != content:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f'Fixed: {fname}')
        files_fixed += 1

print(f'\nTotal files fixed: {files_fixed}')
