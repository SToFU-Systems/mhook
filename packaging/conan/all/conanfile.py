import os

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir


class MhookConan(ConanFile):
    name = "mhook-fork-dev"
    license = "MIT"
    url = "https://github.com/conan-io/conan-center-index"
    homepage = "https://github.com/SToFU-Systems/mhook"
    description = "SToFU Systems fork of the Mhook Windows API hooking library"
    package_type = "static-library"
    settings = "os", "arch", "compiler", "build_type"

    def validate(self):
        if self.settings.os != "Windows" or self.settings.arch not in ("x86", "x86_64"):
            raise ConanInvalidConfiguration("Mhook supports Windows x86 and x86_64 only")

    def layout(self):
        cmake_layout(self)

    def source(self):
        get(self, **self.conan_data["sources"][self.version], strip_root=True)

    def generate(self):
        toolchain = CMakeToolchain(self)
        toolchain.cache_variables["BUILD_TESTING"] = False
        toolchain.cache_variables["MHOOK_BUILD_EXAMPLES"] = False
        toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        copy(self, "LICENSE", src=self.source_folder,
             dst=os.path.join(self.package_folder, "licenses"))
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))
        rmdir(self, os.path.join(self.package_folder, "share"))

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "mhook")

        headers = self.cpp_info.components["headers"]
        headers.set_property("cmake_target_name", "mhook::headers")

        library = self.cpp_info.components["mhook"]
        library.set_property("cmake_target_name", "mhook::mhook")
        library.libs = ["mhook"]
        library.requires = ["headers"]
