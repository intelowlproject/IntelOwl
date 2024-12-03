import flask
from flask import Flask, request, jsonify
import requests
import os
import yaml
import zipfile
from datetime import datetime
import yara
import logging
import json
from typing import Dict, List, Tuple

class YaraForgeManager:
    def __init__(self):
        """Initialize the YARA-Forge manager"""
        self.base_url = "https://api.github.com/repos/YARAHQ/yara-forge"
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create necessary directories
        self.base_dir = "yara_forge_data"
        self.rules_dir = os.path.join(self.base_dir, "rules")
        self.logs_dir = os.path.join(self.base_dir, "logs")
        self.cache_file = os.path.join(self.base_dir, "cache.json")
        
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)

    def _load_cache(self) -> dict:
        """Load cached information about the last downloaded release."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def _save_cache(self, release_info: dict):
        """Save release information to cache."""
        cache_data = {
            'last_release_id': release_info['id'],
            'last_release_tag': release_info['tag_name'],
            'last_update': datetime.now().isoformat(),
            'rules_directory': self.get_latest_rules_dir()
        }
        
        with open(self.cache_file, 'w') as f:
            json.dump(cache_data, f)

    def get_latest_rules_dir(self) -> str:
        """Get the most recent rules directory based on timestamp."""
        rule_dirs = [d for d in os.listdir(self.rules_dir) 
                    if os.path.isdir(os.path.join(self.rules_dir, d))]
        if not rule_dirs:
            return None
        return os.path.join(self.rules_dir, sorted(rule_dirs)[-1])

    def get_latest_release(self) -> dict:
        """Get the latest release information from YARA-Forge."""
        response = requests.get(f"{self.base_url}/releases/latest")
        response.raise_for_status()
        return response.json()

    def _needs_update(self, latest_release: dict) -> Tuple[bool, str]:
        """
        Check if rules need to be updated
        
        Returns:
            Tuple of (needs_update: bool, reason: str)
        """
        cache = self._load_cache()
        
        if not cache:
            return True, "No cached version found"
        
        if not cache.get('rules_directory') or not os.path.exists(cache['rules_directory']):
            return True, "No local rules found"
            
        if cache.get('last_release_id') != latest_release['id']:
            return True, f"New version available (Current: {cache.get('last_release_tag')}, Latest: {latest_release['tag_name']})"
            
        return False, "Rules are up to date"

    def download_release_assets(self, release: dict) -> Dict[str, str]:
        """Download all assets from a release."""
        downloaded_files = {}
        
        for asset in release['assets']:
            asset_name = asset['name']
            download_url = asset['browser_download_url']
            
            local_path = os.path.join(self.base_dir, asset_name)
            
            self.logger.info(f"Downloading {asset_name}")
            response = requests.get(download_url)
            response.raise_for_status()
            
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            downloaded_files[asset_name] = local_path
            
        return downloaded_files

    def extract_rules(self, zip_path: str) -> str:
        """Extract YARA rules from the ZIP archive."""
        extract_dir = os.path.join(self.rules_dir, datetime.now().strftime("%Y%m%d_%H%M%S"))
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        return extract_dir

    def parse_issues(self, issues_path: str) -> dict:
        """Parse the issues YAML file."""
        with open(issues_path, 'r') as f:
            return yaml.safe_load(f)

    def compile_rules(self, rules_dir: str) -> yara.Rules:
        """Compile all YARA rules in the directory."""
        filepaths = {}
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    filepath = os.path.join(root, file)
                    filepaths[os.path.basename(file)] = filepath
        
        return yara.compile(filepaths=filepaths)

    def analyze_file(self, rules: yara.Rules, file_path: str) -> List[dict]:
        """Analyze a file using the compiled YARA rules."""
        matches = rules.match(file_path)
        return [
            {
                'rule': match.rule,
                'tags': match.tags,
                'strings': match.strings,
                'meta': match.meta
            }
            for match in matches
        ]

    def run_update(self, force: bool = False) -> yara.Rules:
        """
        Main method to update and process YARA rules.
        
        Args:
            force: If True, force update regardless of cache
            
        Returns:
            Compiled YARA rules object
        """
        try:
            # Get latest release
            self.logger.info("Checking for updates")
            latest_release = self.get_latest_release()
            
            needs_update, reason = self._needs_update(latest_release)
            if force:
                needs_update, reason = True, "Force update requested"
            
            self.logger.info(reason)
            
            if needs_update:
                # Download and process new rules
                self.logger.info("Downloading new release assets")
                assets = self.download_release_assets(latest_release)
                
                # Find the rules package (ZIP file)
                zip_file = next(
                    (path for name, path in assets.items() if name.endswith('.zip')),
                    None
                )
                if not zip_file:
                    raise ValueError("No rules package found in release assets")
                
                # Extract rules
                self.logger.info("Extracting rules")
                rules_dir = self.extract_rules(zip_file)
                
                # Parse issues if available
                issues_file = next(
                    (path for name, path in assets.items() if name.endswith('.yaml')),
                    None
                )
                if issues_file:
                    self.logger.info("Parsing issues file")
                    issues = self.parse_issues(issues_file)
                
                # Save cache information
                self._save_cache(latest_release)
            else:
                # Use existing rules
                rules_dir = self._load_cache()['rules_directory']
                self.logger.info(f"Using cached rules from: {rules_dir}")
            
            # Compile rules
            self.logger.info("Compiling rules")
            compiled_rules = self.compile_rules(rules_dir)
            
            self.logger.info("Update completed successfully")
            return compiled_rules
            
        except Exception as e:
            self.logger.error(f"Error during update: {str(e)}")
            raise

def main():
    # Initialize the manager
    manager = YaraForgeManager()
    
    # Update rules (with optional force flag)
    compiled_rules = manager.run_update(force=False)
    
    # Example usage of the analyzer
    file_to_analyze = "yara64.exe"
    if not os.path.exists(file_to_analyze):
        print(f"Error: File '{file_to_analyze}' not found!")
        print(f"Current working directory: {os.getcwd()}")
        return
        
    matches = manager.analyze_file(compiled_rules, file_to_analyze)
    if not matches:
        print(f"No YARA rules matched for file: {file_to_analyze}")
    else:
        print(f"\nAnalysis results for {file_to_analyze}:")
        for match in matches:
            print(f"Rule matched: {match['rule']}")
            print(f"Tags: {match['tags']}")
            print(f"Meta: {match['meta']}")
            print("Strings:")
            for string in match['strings']:
                print(f"  - {string}")
            print("---")

if __name__ == "__main__":
    main()

app = Flask(__name__)
manager = YaraForgeManager()

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    temp_path = "/tmp/temp_file"
    file.save(temp_path)
    
    try:
        compiled_rules = manager.get_compiled_rules()
        matches = manager.analyze_file(compiled_rules, temp_path)
        return jsonify({
            'success': True,
            'matches': matches
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)
