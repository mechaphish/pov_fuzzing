import os
import sys
import logging
logging.basicConfig()
l = logging.getLogger("main_type2")
l.setLevel("INFO")
import tempfile
import subprocess

from farnsworth.models import Exploit, PovFuzzer2Job, Test

import pov_fuzzing

# make compilerex executable
import compilerex
bin_path = os.path.join(os.path.dirname(compilerex.__file__), "../bin")
for f in os.listdir(bin_path):
    os.chmod(os.path.join(bin_path, f), 0777)
    os.chmod(os.path.join(bin_path, f), 0777)

# make fake_single executable
fakesingle_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bin/fakesingle")
os.chmod(fakesingle_path, 0777)

def _test_exploit(pov, binaries):
    f1 = tempfile.mktemp(suffix=".pov")
    with open(f1, "wb") as f:
        f.write(pov)
    os.chmod(f1, 0777)

    args  = ["cb-test", "--negotiate", "--cb"]
    args += binaries
    args += ["--directory", ".", "--timeout", "3", "--should_core", "--xml", f1]

    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    os.remove(f1)

    if any(line.startswith("not ok") for line in stdout.split("\n")):
        return False

    if any(line.startswith("ok - TYPE") for line in stdout.split("\n")):
        return True
    return False

def _get_pov_score(fuzzer):
    pov = fuzzer.dump_binary()
    binaries = fuzzer.binaries
    return [_test_exploit(pov, binaries) for _ in range(10)].count(True) / 10.0


if len(sys.argv) != 2:
    print "Usage:", "job_id"

job_id = int(sys.argv[1])

job = PovFuzzer2Job.find(job_id)
if job is None:
    raise Exception("Couldn't find job %d", job_id)

if job.cs.is_multi_cbn:
    cbnp = map(lambda c: c.path, job.cs.cbns_original)
else:
    cbnp = job.cs.cbns_original[0]

cbn = job.cs.cbns_original[0]
crash = job.input_crash

crash_payload = str(crash.blob)
if len(crash_payload) > 20000:
    l.warning("payload has %d bytes, refusing to run", len(crash_payload))
    sys.exit(0)

l.info("Pov fuzzer 2 beginning to exploit crash %d for challenge %s", crash.id, job.cs.name)
pov_fuzzer = pov_fuzzing.Type2CrashFuzzer(cbnp, crash=crash_payload)

crashing_test = job.input_crash

if pov_fuzzer.exploitable():
    e = Exploit.create(cs=job.cs, job=job, pov_type='type2',
                   method="fuzzer",
                   c_code=pov_fuzzer.dump_c(),
                   blob=pov_fuzzer.dump_binary(),
                   crash=crashing_test)
    e.reliability = _get_pov_score(pov_fuzzer)
    e.save()
    l.info("crash was able to be exploited")
else:
    l.warning("Not exploitable")

if pov_fuzzer.dumpable():
    # FIXME: we probably want to store it in a different table with custom attrs
    Test.create(cs=job.cs, job=job, blob=pov_fuzzer.get_leaking_payload())
    l.info("possible leaking test was created")
else:
    l.warning("Couldn't even dump a leaking input")
