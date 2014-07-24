import os
import ycm_core
import subprocess
from clang_helpers import PrepareClangFlags

database = None

def pkg_config(pkg):
    def not_whitespace(string):
        return not (string == '' or string == '\n')
    output = subprocess.check_output(['pkg-config', '--cflags', pkg]).strip()
    return filter(not_whitespace, output.split(' '))

flags = [
  '-Wall',
  '-Wextra',
  '-Werror',
  '-pedantic',
  '-Wshadow', '-Wpointer-arith', '-Wcast-qual', '-Wstrict-prototypes', '-Wmissing-prototypes',
  '-DNDEBUG',
  '-DUSE_CLANG_COMPLETER',
  '-DENVOY_VERSION="ycm"',
  '-D_GNU_SOURCE',
  '-std=c11',
  '-x', 'c'
]

flags += pkg_config('dbus-1')
flags += pkg_config('libsystemd-daemon')

def DirectoryOfThisScript():
  return os.path.dirname(os.path.abspath( __file__ ))

def MakeRelativePathsInFlagsAbsolute( flags, working_directory ):
  if not working_directory:
    return flags
  new_flags = []
  make_next_absolute = False
  path_flags = [ '-isystem', '-I', '-iquote', '--sysroot=' ]
  for flag in flags:
    new_flag = flag

    if make_next_absolute:
      make_next_absolute = False
      if not flag.startswith('/'):
        new_flag = os.path.join(working_directory, flag)

    for path_flag in path_flags:
      if flag == path_flag:
        make_next_absolute = True
        break

      if flag.startswith(path_flag):
        path = flag[len(path_flag):]
        new_flag = path_flag + os.path.join(working_directory, path)
        break

    if new_flag:
      new_flags.append(new_flag)
  return new_flags

def FlagsForFile(filename):
  if database:
    # Bear in mind that compilation_info.compiler_flags_ does NOT return a
    # python list, but a "list-like" StringVec object
    compilation_info = database.GetCompilationInfoForFile(filename)
    final_flags = PrepareClangFlags(
        MakeRelativePathsInFlagsAbsolute(compilation_info.compiler_flags_,
                                         compilation_info.compiler_working_dir_),
        filename)
  else:
    relative_to = DirectoryOfThisScript()
    final_flags = MakeRelativePathsInFlagsAbsolute(flags, relative_to)

  return {
    'flags': final_flags,
    'do_cache': True
  }
