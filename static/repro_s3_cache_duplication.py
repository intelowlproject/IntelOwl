import os
import tempfile

MEDIA_ROOT = tempfile.mkdtemp(prefix="intelowl_media_")


class FakeFile:
    def __init__(self, name):
        self.name = name


class FakeS3Obj:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return self.payload

    def seek(self, _):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class ReproStorage:
    open_calls = 0

    def exists(self, name):
        return True

    def open(self, name):
        self.open_calls += 1
        return FakeS3Obj(b"same-sample-content")

    # mirrors current intel_owl/settings/storage.py logic
    def retrieve(self, file, analyzer):
        path_dir = os.path.join(MEDIA_ROOT, analyzer)
        name = file.name
        _path = os.path.join(path_dir, name)

        if not os.path.exists(_path):
            os.makedirs(path_dir, exist_ok=True)
            os.makedirs(os.path.dirname(_path), exist_ok=True)

            if not self.exists(name):
                raise AssertionError

            with self.open(name) as s3_file_object:
                content = s3_file_object.read()
                s3_file_object.seek(0)
                with open(_path, "wb") as local_file_object:
                    local_file_object.write(content)

        return _path


def main():
    storage = ReproStorage()
    file = FakeFile("samples/sha256_abcd1234.bin")
    analyzers = [f"analyzer_{i}" for i in range(1, 11)]

    paths = [storage.retrieve(file, a) for a in analyzers]

    existing_files = []
    for root, _, files in os.walk(MEDIA_ROOT):
        for f in files:
            existing_files.append(os.path.join(root, f))

    print("MEDIA_ROOT:", MEDIA_ROOT)
    print("Analyzer count:", len(analyzers))
    print("Unique returned paths:", len(set(paths)))
    print("Local cached file count:", len(existing_files))
    print("S3 open() calls:", storage.open_calls)
    print("--- sample paths ---")
    for p in paths[:3]:
        print(p)
    print("...")
    print(paths[-1])

    print("--- cached files (relative, bytes) ---")
    sizes = sorted(
        (os.path.relpath(p, MEDIA_ROOT), os.path.getsize(p)) for p in existing_files
    )
    for rel, size in sizes:
        print(rel, size)


if __name__ == "__main__":
    main()