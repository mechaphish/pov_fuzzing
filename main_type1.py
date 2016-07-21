import sys
import logging
logging.basicConfig()
l = logging.getLogger("main_type1")
l.setLevel("INFO")
import tempfile
import subprocess

from farnsworth.models import Exploit, PovFuzzer1Job

import pov_fuzzing
import os

# make compilerex executable
import compilerex
bin_path = os.path.join(os.path.dirname(compilerex.__file__), "../bin")
for f in os.listdir(bin_path):
    os.chmod(os.path.join(bin_path, f), 0777)
    os.chmod(os.path.join(bin_path, f), 0777)

def _test_exploit(pov, binary):
    f1 = tempfile.mktemp(suffix=".pov")
    with open(f1, "wb") as f:
        f.write(pov)
    os.chmod(f1, 0777)
    args = ["cb-test", "--negotiate", "--cb", binary, "--directory", ".", "--timeout", "3", "--should_core", "--xml", f1]
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
    binary = fuzzer.binary
    return [_test_exploit(pov, binary) for _ in range(10)].count(True) / 10.0

if len(sys.argv) != 2:
    print "Usage:", "job_id"

job_id = int(sys.argv[1])

job = PovFuzzer1Job.find(job_id)
if job is None:
    raise Exception("Couldn't find job %d", job_id)

if job.cs.is_multi_cbn:
    cbnp = map(lambda c: c.path, job.cs.cbns_original)
else:
    cbnp = job.cs.cbns_original[0].path

crash = job.input_crash

crash_payload = str(crash.blob)
if len(crash_payload) > 20000:
    l.warning("payload has %d bytes, refusing to run", len(crash_payload))
    sys.exit(0)

l.info("Pov fuzzer 1 beginning to exploit crash %d for challenge %s", crash.id, job.cs.name)
pov_fuzzer = pov_fuzzing.Type1CrashFuzzer(cbnp, crash=crash_payload)

crashing_test = job.input_crash

if pov_fuzzer.exploitable():
    e = Exploit.create(cs=job.cs, job=job, pov_type='type1',
                       method="fuzzer",
                       c_code=pov_fuzzer.dump_c(),
                       blob=pov_fuzzer.dump_binary(),
                       crash=crashing_test)
    e.reliability = _get_pov_score(pov_fuzzer)
    e.save()

    l.info("crash was able to be exploited")
else:
    l.warning("Not exploitable")
