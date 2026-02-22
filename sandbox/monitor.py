# sandbox/monitor.py
import subprocess
import json
import sys
import os
import time
import psutil
from threading import Thread
import signal
import glob

class BehaviorMonitor:
    def __init__(self):
        self.behaviors = []
        self.file_changes = []
        self.network_activity = []
        self.process_activity = []
        self.monitoring = True
        self.initial_files = set()
        
    def snapshot_files(self, watch_dirs):
        """Take initial snapshot of files"""
        files = set()
        for directory in watch_dirs:
            try:
                for root, dirs, filenames in os.walk(directory):
                    for filename in filenames:
                        files.add(os.path.join(root, filename))
            except:
                pass
        return files
    
    def monitor_files(self, watch_dirs=["/tmp", "/tmp/wine"]):
        """Monitor file system changes"""
        self.initial_files = self.snapshot_files(watch_dirs)
        
        while self.monitoring:
            try:
                current_files = self.snapshot_files(watch_dirs)
                
                # New files
                new_files = current_files - self.initial_files
                for f in new_files:
                    if not f.endswith('.log') and '.wine' not in f:  # Filter Wine logs
                        self.file_changes.append({
                            "action": "FILE_CREATED",
                            "path": f,
                            "severity": "MEDIUM"
                        })
                
                # Deleted files
                deleted_files = self.initial_files - current_files
                for f in deleted_files:
                    self.file_changes.append({
                        "action": "FILE_DELETED",
                        "path": f,
                        "severity": "HIGH"
                    })
                
                self.initial_files = current_files
                time.sleep(2)
            except Exception as e:
                time.sleep(2)
    
    def monitor_network(self):
        """Monitor network connections"""
        initial_connections = set()
        try:
            initial_connections = {
                f"{conn.laddr.ip}:{conn.laddr.port}"
                for conn in psutil.net_connections()
                if conn.status == 'ESTABLISHED'
            }
        except:
            pass
        
        while self.monitoring:
            try:
                current_connections = {
                    f"{conn.laddr.ip}:{conn.laddr.port}"
                    for conn in psutil.net_connections()
                    if conn.status == 'ESTABLISHED'
                }
                
                new_connections = current_connections - initial_connections
                for conn in new_connections:
                    self.network_activity.append({
                        "action": "NETWORK_CONNECTION",
                        "connection": conn,
                        "severity": "HIGH"
                    })
                
                initial_connections = current_connections
                time.sleep(2)
            except Exception as e:
                time.sleep(2)
    
    def monitor_processes(self):
        """Monitor process creation"""
        try:
            initial_pids = {p.pid for p in psutil.process_iter(['pid'])}
        except:
            initial_pids = set()
        
        while self.monitoring:
            try:
                current_pids = {p.pid for p in psutil.process_iter(['pid'])}
                new_pids = current_pids - initial_pids
                
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        
                        # Filter out system processes
                        if name not in ['python3', 'ps', 'sh', 'wine', 'wineserver']:
                            self.process_activity.append({
                                "action": "PROCESS_CREATED",
                                "name": name,
                                "pid": pid,
                                "severity": "MEDIUM"
                            })
                    except:
                        pass
                
                initial_pids = current_pids
                time.sleep(1)
            except Exception as e:
                time.sleep(1)
    
    def analyze_behaviors(self):
        """Analyze collected behaviors"""
        all_behaviors = []
        severity_score = 0
        
        # Process file changes
        for change in self.file_changes[:10]:  # Limit to 10
            severity_score += 20 if change["severity"] == "HIGH" else 10
            all_behaviors.append({
                "type": "File Operation",
                "description": f"{change['action']}: {os.path.basename(change['path'])}",
                "severity": change["severity"]
            })
        
        # Process network activity
        for conn in self.network_activity[:10]:
            severity_score += 50
            all_behaviors.append({
                "type": "Network Activity",
                "description": f"Connection established: {conn['connection']}",
                "severity": "HIGH"
            })
        
        # Process new processes
        for proc in self.process_activity[:10]:
            severity_score += 20
            all_behaviors.append({
                "type": "Process Activity",
                "description": f"Process created: {proc['name']}",
                "severity": "MEDIUM"
            })
        
        # Determine threat level
        if severity_score >= 100:
            threat_level = "CRITICAL"
        elif severity_score >= 50:
            threat_level = "HIGH"
        elif severity_score >= 20:
            threat_level = "MEDIUM"
        elif severity_score > 0:
            threat_level = "LOW"
        else:
            threat_level = "SAFE"
        
        return {
            "behaviors": all_behaviors,
            "threat_level": threat_level,
            "severity_score": severity_score,
            "file_changes_count": len(self.file_changes),
            "network_connections_count": len(self.network_activity),
            "processes_created_count": len(self.process_activity)
        }

def run_executable(file_path, timeout=30):
    """Execute file and monitor behavior"""
    monitor = BehaviorMonitor()
    
    # Start monitoring threads
    threads = [
        Thread(target=monitor.monitor_files, daemon=True),
        Thread(target=monitor.monitor_network, daemon=True),
        Thread(target=monitor.monitor_processes, daemon=True)
    ]
    
    for t in threads:
        t.start()
    
    # Wait for monitors to initialize
    time.sleep(2)
    
    try:
        # Determine execution method
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Redirect Wine errors to /dev/null
        wine_env = os.environ.copy()
        wine_env['WINEDEBUG'] = '-all'
        
        if file_ext in ['.exe', '.dll', '.bat']:
            # Execute with Wine - redirect stderr
            cmd = ["wine64", file_path]
            devnull = open(os.devnull, 'w')
            stderr_output = devnull
        elif file_ext in ['.py']:
            cmd = ["python3", file_path]
            stderr_output = subprocess.PIPE
        elif file_ext in ['.sh']:
            cmd = ["bash", file_path]
            stderr_output = subprocess.PIPE
        else:
            # Try to execute directly
            cmd = [file_path]
            stderr_output = subprocess.PIPE
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=stderr_output,
            env=wine_env,
            preexec_fn=os.setsid
        )
        
        # Wait for timeout
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.communicate()
        
        if file_ext in ['.exe', '.dll', '.bat']:
            devnull.close()
        
    except Exception as e:
        # Don't print to stderr, just continue
        pass
    
    finally:
        # Stop monitoring
        time.sleep(3)  # Let monitors catch final events
        monitor.monitoring = False
        
        for t in threads:
            t.join(timeout=2)
    
    return monitor.analyze_behaviors()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        result = {"error": "No file path provided"}
    else:
        file_path = sys.argv[1]
        
        if not os.path.exists(file_path):
            result = {"error": f"File not found: {file_path}"}
        else:
            result = run_executable(file_path, timeout=30)
    
    # Output ONLY JSON to stdout
    print(json.dumps(result))
    sys.stdout.flush()