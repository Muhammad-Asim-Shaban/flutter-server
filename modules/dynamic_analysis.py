# modules/dynamic_analysis.py

import docker
import json
import os
import time
import shutil
import tempfile

class DynamicAnalyzer:
    def __init__(self):
        self.enabled = False
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.sandbox_image = "malware-sandbox:latest"
            self.timeout = 60
            self.enabled = True
            print("✅ Docker sandbox initialized successfully")
        except Exception as e:
            print(f"⚠️ Docker not available: {e}")
            print("   Dynamic analysis will be disabled")
            self.client = None

    def analyze_file(self, file_path, file_name):
        """
        Analyze a file in a sandboxed Docker environment
        
        Args:
            file_path: Full path to the file on host
            file_name: Name of the file
            
        Returns:
            Dictionary with runtime behavior analysis
        """
        if not self.enabled:
            return self._get_disabled_result()

        sandbox_dir = None
        container = None

        try:
            # ---------------- CREATE SANDBOX COPY ---------------- #
            sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")
            sandbox_file_path = os.path.join(sandbox_dir, file_name)

            # Copy file to sandbox directory
            shutil.copy2(file_path, sandbox_file_path)
            os.chmod(sandbox_file_path, 0o755)  # Make executable

            container_file_path = f"/malware/{file_name}"

            print(f"🐳 Starting sandbox analysis for: {file_name}")
            print(f"   Sandbox dir: {sandbox_dir}")

            # ---------------- RUN CONTAINER ---------------- #
            container = self.client.containers.run(
                self.sandbox_image,
                command=container_file_path,
                volumes={sandbox_dir: {'bind': '/malware', 'mode': 'rw'}},
                network_mode="none",
                mem_limit="512m",
                cpu_quota=50000,
                detach=True,
                remove=False,
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"]
            )

            print(f"   Container ID: {container.short_id}")

            # ---------------- WAIT FOR COMPLETION ---------------- #
            start_time = time.time()
            timeout_reached = False
            
            while True:
                container.reload()
                
                if container.status == "exited":
                    print(f"   Container exited naturally")
                    break
                    
                if time.time() - start_time > self.timeout:
                    print(f"⏰ Sandbox timeout ({self.timeout}s) — killing container")
                    container.kill()
                    timeout_reached = True
                    break
                    
                time.sleep(1)

            # Wait a moment for container to fully release resources
            time.sleep(2)

            # ---------------- COLLECT OUTPUT ---------------- #
            stdout_logs = container.logs(stdout=True, stderr=False).decode(
                "utf-8", errors="ignore"
            )

            stderr_logs = container.logs(stdout=False, stderr=True).decode(
                "utf-8", errors="ignore"
            )

            if stderr_logs:
                print(f"📝 Container stderr (first 200 chars): {stderr_logs[:200]}")

            print(f"📤 Container stdout (first 300 chars): {stdout_logs[:300]}")

            # Clean up container
            container.remove(force=True)
            container = None

            # ---------------- PARSE JSON RESULT ---------------- #
            # Look for JSON output from the end of stdout
            result_json = None
            
            for line in reversed(stdout_logs.splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        result_json = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue

            if result_json:
                print(f"✅ Sandbox analysis complete: {result_json.get('threat_level', 'UNKNOWN')}")
                print(f"   Behaviors detected: {len(result_json.get('behaviors', []))}")
                print(f"   Severity score: {result_json.get('severity_score', 0)}")
                return result_json
            else:
                print(f"⚠️ No valid JSON output found in container logs")
                return self._get_error_result(
                    "No valid JSON output from sandbox. File may not be executable or crashed."
                )

        except docker.errors.ImageNotFound:
            print(f"❌ Docker image '{self.sandbox_image}' not found")
            return self._get_error_result(
                f"Sandbox image '{self.sandbox_image}' not found. Please build it first:\n"
                "cd sandbox && docker build -t malware-sandbox:latest ."
            )

        except docker.errors.APIError as e:
            print(f"❌ Docker API error: {e}")
            return self._get_error_result(f"Docker API error: {str(e)}")

        except Exception as e:
            import traceback
            print(f"❌ Unexpected error during dynamic analysis:")
            traceback.print_exc()
            return self._get_error_result(f"Unexpected error: {str(e)}")

        finally:
            # ---------------- CLEANUP ---------------- #
            try:
                if container:
                    container.remove(force=True)
                    print(f"🧹 Container removed")
                    # Wait for Docker to fully release resources
                    time.sleep(1)
            except Exception as e:
                print(f"⚠️ Error removing container: {e}")

            if sandbox_dir and os.path.exists(sandbox_dir):
                # Retry cleanup logic for Windows
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        shutil.rmtree(sandbox_dir, ignore_errors=True)
                        print(f"🧹 Sandbox directory cleaned up")
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            print(f"⏳ Retrying cleanup ({attempt + 1}/{max_retries})...")
                            time.sleep(2)
                        else:
                            print(f"⚠️ Error cleaning up sandbox dir: {e}")

    def _get_disabled_result(self):
        """Return result when Docker is not available"""
        return {
            "behaviors": [{
                "type": "System",
                "description": "Dynamic analysis unavailable - Docker not running",
                "severity": "INFO"
            }],
            "threat_level": "UNKNOWN",
            "severity_score": 0,
            "file_changes_count": 0,
            "network_connections_count": 0,
            "processes_created_count": 0,
            "timeout_reached": False
        }

    def _get_error_result(self, error_msg):
        """Return result when an error occurs"""
        return {
            "error": error_msg,
            "behaviors": [{
                "type": "System",
                "description": f"Analysis error: {error_msg}",
                "severity": "INFO"
            }],
            "threat_level": "UNKNOWN",
            "severity_score": 0,
            "file_changes_count": 0,
            "network_connections_count": 0,
            "processes_created_count": 0,
            "timeout_reached": False
        }