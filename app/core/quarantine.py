import hashlib
import json
import os
import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import List, Optional

from app.core.logger import get_logger

logger = get_logger()

@dataclass
class QuarantineItem:
    id: str
    original_path: str
    quarantine_filename: str
    threat_name: str
    quarantine_time: str
    file_size: int
    sha256: str

class QuarantineManager:
    def __init__(self, quarantine_dir: str):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def _calc_sha256(self, file_path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def quarantine_file(self, file_path: str, threat_name: str) -> Optional[QuarantineItem]:
        if not os.path.exists(file_path):
            logger.warning(f"Cannot quarantine non-existent file: {file_path}")
            return None

        try:
            file_id = str(uuid.uuid4())
            file_size = os.path.getsize(file_path)
            file_hash = self._calc_sha256(file_path)
            quarantine_filename = f"{file_id}.quarantine"
            dest_path = os.path.join(self.quarantine_dir, quarantine_filename)

            # Move file to quarantine
            shutil.move(file_path, dest_path)

            item = QuarantineItem(
                id=file_id,
                original_path=file_path,
                quarantine_filename=quarantine_filename,
                threat_name=threat_name,
                quarantine_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                file_size=file_size,
                sha256=file_hash,
            )

            # Save metadata
            meta_path = os.path.join(self.quarantine_dir, f"{file_id}.json")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(asdict(item), f, indent=2)

            logger.info(f"Quarantined {file_path} -> {dest_path} (Threat: {threat_name})")
            return item
        except Exception as exc:
            logger.error(f"Failed to quarantine {file_path}: {exc}")
            return None

    def list_items(self) -> List[QuarantineItem]:
        items: List[QuarantineItem] = []
        if not os.path.exists(self.quarantine_dir):
            return items

        for fname in os.listdir(self.quarantine_dir):
            if fname.endswith(".json"):
                meta_path = os.path.join(self.quarantine_dir, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    valid_fields = {k: v for k, v in data.items() if k in QuarantineItem.__dataclass_fields__}
                    items.append(QuarantineItem(**valid_fields))
                except Exception as exc:
                    logger.warning(f"Corrupted quarantine metadata {meta_path}: {exc}")
        # Sort newest first
        items.sort(key=lambda x: x.quarantine_time, reverse=True)
        return items

    def restore_item(self, item_id: str) -> bool:
        meta_path = os.path.join(self.quarantine_dir, f"{item_id}.json")
        if not os.path.exists(meta_path):
            logger.error(f"Quarantine item {item_id} metadata not found")
            return False

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            valid_fields = {k: v for k, v in data.items() if k in QuarantineItem.__dataclass_fields__}
            item = QuarantineItem(**valid_fields)

            stored_file = os.path.join(self.quarantine_dir, item.quarantine_filename)
            if not os.path.exists(stored_file):
                logger.error(f"Quarantined file {stored_file} not found on disk")
                return False

            orig_dir = os.path.dirname(item.original_path)
            if orig_dir:
                os.makedirs(orig_dir, exist_ok=True)

            dest_path = item.original_path
            # If a file already exists at original path, save with _restored suffix to avoid collision
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(dest_path)
                candidate = f"{base}_restored{ext}"
                counter = 1
                while os.path.exists(candidate):
                    candidate = f"{base}_restored_{counter}{ext}"
                    counter += 1
                dest_path = candidate

            shutil.move(stored_file, dest_path)
            os.remove(meta_path)
            logger.info(f"Restored {stored_file} -> {dest_path}")
            return True
        except Exception as exc:
            logger.error(f"Failed to restore item {item_id}: {exc}")
            return False

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            if os.name == "nt" and os.path.exists(path):
                os.chmod(path, 0o777)
            os.remove(path)
        except Exception as exc:
            logger.debug(f"Could not remove {path}: {exc}")

    def delete_item(self, item_id: str) -> bool:
        meta_path = os.path.join(self.quarantine_dir, f"{item_id}.json")
        raw_file = os.path.join(self.quarantine_dir, f"{item_id}.quarantine")
        try:
            # Delete physical quarantine payload if found
            if os.path.exists(raw_file):
                self._safe_remove(raw_file)

            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                valid_fields = {k: v for k, v in data.items() if k in QuarantineItem.__dataclass_fields__}
                item = QuarantineItem(**valid_fields)
                stored_file = os.path.join(self.quarantine_dir, item.quarantine_filename)
                if os.path.exists(stored_file):
                    self._safe_remove(stored_file)
                self._safe_remove(meta_path)
                logger.info(f"Permanently deleted quarantined item {item_id}")
                return True
            elif not os.path.exists(raw_file):
                return False
            return True
        except Exception as exc:
            logger.error(f"Failed to delete item {item_id}: {exc}")
            return False
