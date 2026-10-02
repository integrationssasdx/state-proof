"""JSON 原子写入：同目录临时文件 + fsync + os.replace。

任何失败都不会在目标路径留下部分写入的内容；失败统一抛 InputError。
"""

import json
import os
import tempfile

from .errors import InputError


def atomic_write_json(path, data, *, indent=2):
    directory = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        raise InputError(f"无法创建输出目录: {path}: {exc}") from exc

    payload = json.dumps(data, ensure_ascii=False, indent=indent) + "\n"
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(
            dir=directory,
            prefix="." + os.path.basename(path) + ".",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except OSError:
            raise
    except OSError as exc:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise InputError(f"无法原子写入文件: {path}: {exc}") from exc
