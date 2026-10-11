import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


def check(path: Path) -> None:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            assert {"tesla_ble/_tesla_ble.pyi", "tesla_ble/py.typed"} <= set(names), path
            assert not any(
                name.startswith(("include/", "lib/", "lib64/", "bin/")) for name in names
            ), path
            metadata = BytesParser().parsebytes(
                archive.read(next(n for n in names if n.endswith("/METADATA")))
            )
            assert metadata["License-Expression"] == "AGPL-3.0-only", path
            license_name = next(n for n in names if n.endswith("/licenses/LICENSE"))
            assert b"GNU AFFERO GENERAL PUBLIC LICENSE" in archive.read(license_name), path
            assert any(n.endswith("/licenses/NOTICE") for n in names), path
            for dependency in ("mbedtls", "nanopb"):
                assert f"tesla_ble/licenses/{dependency}.txt" in names, path
    else:
        with tarfile.open(path) as archive:
            names = [member.name.partition("/")[2] for member in archive.getmembers()]
            assert not any(".zvec-grep" in Path(name).parts for name in names), path
            assert {
                "VERSION",
                "CMakeLists.txt",
                "bindings/python/CMakeLists.txt",
                "src/vehicle.cpp",
            } <= set(names), path
    print(f"OK: {path.name}")


if __name__ == "__main__":
    artifacts = []
    release_matrix = "--release-matrix" in sys.argv[1:]
    linux_matrix = release_matrix or "--linux-matrix" in sys.argv[1:]
    arguments = [arg for arg in sys.argv[1:] if arg not in ("--linux-matrix", "--release-matrix")]
    for argument in arguments or ["dist"]:
        path = Path(argument)
        artifacts.extend(
            sorted(path.glob("*.whl")) + sorted(path.glob("*.tar.gz")) if path.is_dir() else [path]
        )
    assert artifacts, "No distribution artifacts found"
    for artifact in artifacts:
        check(artifact)
    if linux_matrix:
        for python in ("cp313", "cp314", "cp315"):
            for libc in ("manylinux", "musllinux"):
                for architecture in ("x86_64", "aarch64"):
                    assert any(
                        f"-{python}-{python}-" in artifact.name
                        and f"{libc}_" in artifact.name
                        and artifact.name.endswith(f"_{architecture}.whl")
                        for artifact in artifacts
                    ), f"Missing release wheel: {python} {libc} {architecture}"
        print("OK: complete Linux release matrix (glibc and musl)")
    if release_matrix:
        for python in ("cp313", "cp314", "cp315"):
            for architecture in ("x86_64", "arm64"):
                assert any(
                    f"-{python}-{python}-macosx_" in artifact.name
                    and artifact.name.endswith(f"_{architecture}.whl")
                    for artifact in artifacts
                ), f"Missing release wheel: {python} macOS {architecture}"
        print("OK: complete macOS release matrix (Intel and Apple Silicon)")
