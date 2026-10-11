import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


class ReleaseMatrixTest(unittest.TestCase):
    def test_complete_matrix_and_missing_native_wheel(self) -> None:
        script = Path(__file__).with_name("check_dist.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            platforms = [
                "manylinux_2_28_x86_64",
                "manylinux_2_28_aarch64",
                "musllinux_1_2_x86_64",
                "musllinux_1_2_aarch64",
                "macosx_15_0_x86_64",
                "macosx_15_0_arm64",
            ]
            for python in ("cp313", "cp314", "cp315"):
                for platform in platforms:
                    with zipfile.ZipFile(
                        root / f"tesla_ble-6.0.0-{python}-{python}-{platform}.whl", "w"
                    ) as wheel:
                        wheel.writestr("tesla_ble/_tesla_ble.pyi", "")
                        wheel.writestr("tesla_ble/py.typed", "")
                        wheel.writestr(
                            "tesla_ble-6.0.0.dist-info/METADATA",
                            "License-Expression: AGPL-3.0-only\n",
                        )
                        wheel.writestr(
                            "tesla_ble-6.0.0.dist-info/licenses/LICENSE",
                            "GNU AFFERO GENERAL PUBLIC LICENSE",
                        )
                        wheel.writestr("tesla_ble-6.0.0.dist-info/licenses/NOTICE", "")
                        for dependency in ("mbedtls", "nanopb"):
                            wheel.writestr(f"tesla_ble/licenses/{dependency}.txt", "")
            with tarfile.open(root / "tesla_ble-6.0.0.tar.gz", "w:gz") as sdist:
                for name in (
                    "VERSION",
                    "CMakeLists.txt",
                    "bindings/python/CMakeLists.txt",
                    "src/vehicle.cpp",
                ):
                    sdist.addfile(tarfile.TarInfo(f"tesla_ble-6.0.0/{name}"))
            command = [sys.executable, str(script), "--release-matrix", directory]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for platform in ("macosx_15_0_arm64", "musllinux_1_2_aarch64"):
                missing = root / f"tesla_ble-6.0.0-cp315-cp315-{platform}.whl"
                data = missing.read_bytes()
                missing.unlink()
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Missing release wheel: cp315", result.stderr)
                missing.write_bytes(data)


if __name__ == "__main__":
    unittest.main()
