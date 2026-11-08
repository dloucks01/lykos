"""The CMake configure retry must disable the dependency that FAILED, not one a warning named.

FreeRDP 3.20.0's clean explore build: CMake WARNS that jansson has no CMake config (then finds it
through pkg-config) and ERRORS on `pkg_check_modules(FUSE3 REQUIRED fuse3)` under
`if(WITH_FUSE)`. The old scan read the whole log, disabled jansson, missed fuse3, and gave up --
so the concolic explore harnesses never built."""
from lykos.analyze import libfuzzer as L

LOG = """CMake Warning at cmake/JsonDetect.cmake:6 (find_package):
  Could not find a package configuration file provided by "jansson"
  (requested version 2.13) with any of the following names:

-- Checking for module 'jansson>=2.13'
--   Found jansson, version 2.14
CMake Error at /usr/share/cmake-4.2/Modules/FindPkgConfig.cmake:1093 (message):
  The following required packages were not found:

   - fuse3

Call Stack (most recent call first):
  /usr/share/cmake-4.2/Modules/FindPkgConfig.cmake:1166 (_pkg_check_modules_internal)
  client/common/CMakeLists.txt:7 (pkg_check_modules)


-- Configuring incomplete, errors occurred!
"""


def _tree(tmp_path):
    (tmp_path / "client" / "common").mkdir(parents=True)
    (tmp_path / "client" / "common" / "CMakeLists.txt").write_text(
        'option(WITH_FUSE "fuse" ON)\n'
        "if(WITH_ZZ)\n  message(zz)\nendif()\n"
        "if(WITH_FUSE)\n  find_package(PkgConfig REQUIRED)\n"
        "  pkg_check_modules(FUSE3 REQUIRED fuse3)\nendif()\n")
    return tmp_path


def test_only_error_blocks_name_missing_packages():
    assert L._missing_cmake_pkgs(LOG) == {"fuse3"}


def test_the_guarding_project_option_is_turned_off(tmp_path):
    assert L._guarding_options(_tree(tmp_path), LOG) == {"-DWITH_FUSE=OFF"}


def test_an_if_on_an_undeclared_variable_is_not_an_option(tmp_path):
    root = _tree(tmp_path)
    (root / "client" / "common" / "CMakeLists.txt").write_text(
        "if(UNIX)\n  x()\n  y()\n  z()\n  w()\n  v()\n  pkg_check_modules(FUSE3 REQUIRED fuse3)\nendif()\n")
    L._declared_options.cache_clear()
    assert L._guarding_options(root, LOG) == set()
