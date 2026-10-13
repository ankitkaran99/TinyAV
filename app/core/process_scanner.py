import os
from typing import Dict, List, Set, Tuple

import psutil
from app.core.logger import get_logger

logger = get_logger()

class ProcessFileCollector:
    """
    Collects on-disk executables and loaded DLL modules for all accessible running processes.
    Note: ClamAV does not support direct live RAM inspection on Windows; this collects
    the corresponding on-disk binary files for active processes.
    """

    @staticmethod
    def collect_process_files() -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Returns:
            - list of unique file paths (executables and loaded DLLs)
            - mapping of file_path -> list of process names using it
        """
        unique_paths: Set[str] = set()
        file_to_processes: Dict[str, Set[str]] = {}

        for proc in psutil.process_iter(["pid", "name"]):
            p_name = "Unknown"
            try:
                p_name = (proc.info or {}).get("name") or "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # Process main executable
            try:
                exe = proc.exe()
                if exe and isinstance(exe, str) and os.path.isfile(exe):
                    norm = os.path.normcase(os.path.abspath(exe))
                    unique_paths.add(norm)
                    file_to_processes.setdefault(norm, set()).add(f"{p_name} (PID {proc.pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception as exc:
                logger.debug(f"Failed to get exe for process {p_name}: {exc}")

            # Loaded DLL/module paths
            try:
                maps = proc.memory_maps()
                for m in maps:
                    m_path = getattr(m, "path", None)
                    if m_path and isinstance(m_path, str) and os.path.isfile(m_path):
                        norm = os.path.normcase(os.path.abspath(m_path))
                        unique_paths.add(norm)
                        file_to_processes.setdefault(norm, set()).add(f"{p_name} (PID {proc.pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception as exc:
                logger.debug(f"Failed to get memory maps for process {p_name}: {exc}")

        # Convert mapping values to sorted lists
        mapping_result = {
            path: sorted(list(procs)) for path, procs in file_to_processes.items()
        }

        sorted_paths = sorted(list(unique_paths))
        logger.info(f"Collected {len(sorted_paths)} unique files across running processes.")
        return sorted_paths, mapping_result
