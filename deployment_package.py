"""
Script to create AWS Lambda deployment package.
"""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path


def create_deployment_package():
    """Create AWS Lambda deployment package."""
    
    # Create temporary directory for package
    package_dir = Path('lambda_package')
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir()
    
    print("Creating Lambda deployment package...")
    
    # Install dependencies
    print("Installing dependencies...")
    subprocess.run([
        'pip', 'install', '-r', 'requirements.txt', 
        '-t', str(package_dir)
    ], check=True)
    
    # Copy lambda function
    shutil.copy2('lambda_function.py', package_dir)
    
    # Create zip file
    zip_path = 'nvd_lambda_function.zip'
    if os.path.exists(zip_path):
        os.remove(zip_path)
    
    print("Creating zip file...")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, package_dir)
                zipf.write(file_path, arcname)
    
    # Clean up
    shutil.rmtree(package_dir)
    
    print(f"Deployment package created: {zip_path}")
    print(f"Package size: {os.path.getsize(zip_path) / 1024 / 1024:.2f} MB")


if __name__ == '__main__':
    create_deployment_package()