# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/mxd/clion-2021.2.1/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/mxd/clion-2021.2.1/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mxd/桌面/ebpfStudy

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mxd/桌面/ebpfStudy/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ebpfStudy.dir/depend.make
# Include the progress variables for this target.
include CMakeFiles/ebpfStudy.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ebpfStudy.dir/flags.make

CMakeFiles/ebpfStudy.dir/main.c.o: CMakeFiles/ebpfStudy.dir/flags.make
CMakeFiles/ebpfStudy.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mxd/桌面/ebpfStudy/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/ebpfStudy.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ebpfStudy.dir/main.c.o -c /home/mxd/桌面/ebpfStudy/main.c

CMakeFiles/ebpfStudy.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ebpfStudy.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mxd/桌面/ebpfStudy/main.c > CMakeFiles/ebpfStudy.dir/main.c.i

CMakeFiles/ebpfStudy.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ebpfStudy.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mxd/桌面/ebpfStudy/main.c -o CMakeFiles/ebpfStudy.dir/main.c.s

CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.o: CMakeFiles/ebpfStudy.dir/flags.make
CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.o: ../study/xdp-frop-world.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mxd/桌面/ebpfStudy/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.o -c /home/mxd/桌面/ebpfStudy/study/xdp-frop-world.c

CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/mxd/桌面/ebpfStudy/study/xdp-frop-world.c > CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.i

CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/mxd/桌面/ebpfStudy/study/xdp-frop-world.c -o CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.s

# Object files for target ebpfStudy
ebpfStudy_OBJECTS = \
"CMakeFiles/ebpfStudy.dir/main.c.o" \
"CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.o"

# External object files for target ebpfStudy
ebpfStudy_EXTERNAL_OBJECTS =

ebpfStudy: CMakeFiles/ebpfStudy.dir/main.c.o
ebpfStudy: CMakeFiles/ebpfStudy.dir/study/xdp-frop-world.c.o
ebpfStudy: CMakeFiles/ebpfStudy.dir/build.make
ebpfStudy: CMakeFiles/ebpfStudy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mxd/桌面/ebpfStudy/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable ebpfStudy"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ebpfStudy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ebpfStudy.dir/build: ebpfStudy
.PHONY : CMakeFiles/ebpfStudy.dir/build

CMakeFiles/ebpfStudy.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ebpfStudy.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ebpfStudy.dir/clean

CMakeFiles/ebpfStudy.dir/depend:
	cd /home/mxd/桌面/ebpfStudy/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mxd/桌面/ebpfStudy /home/mxd/桌面/ebpfStudy /home/mxd/桌面/ebpfStudy/cmake-build-debug /home/mxd/桌面/ebpfStudy/cmake-build-debug /home/mxd/桌面/ebpfStudy/cmake-build-debug/CMakeFiles/ebpfStudy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ebpfStudy.dir/depend

