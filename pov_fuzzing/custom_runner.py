import os
import shutil
import signal
import logging
import resource
import tempfile
import subprocess
import contextlib

from .core_loader import CoreLoader, ParseError


l = logging.getLogger("rex.pov_fuzzing.custom_runner")


class RunnerError(Exception):
    pass


class CustomRunner(object):
    def __init__(self, binary, payload, record_stdout=False, grab_crashing_inst=False):
        self.binary = binary
        self.payload = payload
        self._set_memory_limit(1024 * 1024 * 1024)
        self.reg_vals = dict()
        self.crash_mode = False
        self.crashing_inst = None
        self.stdout = None

        # check the binary
        if not os.access(self.binary, os.X_OK):
            if os.path.isfile(self.binary):
                l.error("\"%s\" binary is not executable", self.binary)
                raise RunnerError
            else:
                l.error("\"%s\" binary does not exist", self.binary)
                raise RunnerError

        if record_stdout:
            tmp = tempfile.mktemp(prefix="stdout_" + os.path.basename(binary))
            # will set crash_mode correctly
            self.dynamic_trace(stdout_file=tmp, grab_crashing_inst=grab_crashing_inst)
            with open(tmp, "rb") as f:
                self.stdout = f.read()
            os.remove(tmp)
        else:
            # will set crash_mode correctly
            self.dynamic_trace(grab_crashing_inst=grab_crashing_inst)


    @staticmethod
    def _set_memory_limit(ml):
        resource.setrlimit(resource.RLIMIT_AS, (ml, ml))

    # create a tmp dir in /dev/shm, chdir into it, set rlimit, save the current self.binary
    # at the end, it restores everything
    @contextlib.contextmanager
    def _setup_env(self):
        prefix = "/tmp/tracer_"
        curdir = os.getcwd()
        tmpdir = tempfile.mkdtemp(prefix=prefix)
        # allow cores to be dumped
        saved_limit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        binary_old = self.binary
        binary_replacement_fname = os.path.join(tmpdir, "binary_replacement")
        shutil.copy(self.binary, binary_replacement_fname)
        self.binary = binary_replacement_fname
        os.chdir(tmpdir)
        try:
            yield (tmpdir, binary_replacement_fname)
        finally:
            assert tmpdir.startswith(prefix)
            shutil.rmtree(tmpdir)
            os.chdir(curdir)
            resource.setrlimit(resource.RLIMIT_CORE, saved_limit)
            self.binary = binary_old

    def dynamic_trace(self, stdout_file=None, grab_crashing_inst=False):
        with self._setup_env() as (tmpdir,binary_replacement_fname):
            # get the dynamic trace
            self._run_trace(stdout_file=stdout_file)

            if self.crash_mode:
                # find core file
                core_files = filter(
                        lambda x: x == "core",
                        os.listdir('.')
                        )

                if len(core_files) == 0:
                    l.warning("NO CORE FOUND")
                    self.crash_mode = False
                    return
                a_mesg = "Empty core file generated"
                if os.path.getsize(core_files[0]) == 0:
                    l.warning(a_mesg)
                    self.crash_mode = False
                    return
                self._load_core_values(core_files[0])

                if grab_crashing_inst and self.reg_vals is not None and "eip" in self.reg_vals:
                    p1 = subprocess.Popen([os.path.abspath(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    args = ["sudo", "gdb", "-q", "-batch", "-p", str(p1.pid), "-ex", 'set disassembly-flavor intel', "-ex", 'x/1i ' + hex(self.reg_vals["eip"])]
                    p = subprocess.Popen(args, stdout=subprocess.PIPE)
                    inst, _ = p.communicate()
                    p1.kill()
                    inst = inst.split(":")[-1].strip()
                    self.crashing_inst = inst

    def _run_trace(self, stdout_file=None):
        """
        accumulate a basic block trace using qemu
        """

        args = ["timeout", "-k", "0.05", "0.05", os.path.abspath(self.binary), "seed=0262f0af52bbe292c7f54469239a86b2a8ffaecc6880e7da5e434fd5b57b827b06d9945a47fbdd2f1b2f43a0ff4c1b7f"]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            l.debug("tracing as raw input")
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout_f, stderr=devnull)
            _, _ = p.communicate(self.payload)

            ret = p.wait()
            self.returncode = p.returncode
            # did a crash occur?
            if ret < 0 or ret == 139:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL or ret == 139:
                    l.info("input caused a crash (signal %d) during dynamic tracing", abs(ret))
                    l.debug("entering crash mode")
                    self.crash_mode = True

            if stdout_file is not None:
                stdout_f.close()

    def _load_core_values(self, core_file):
        try:
            self.reg_vals = dict(CoreLoader(core_file).registers)
        except ParseError as e:
            l.warning(e)

