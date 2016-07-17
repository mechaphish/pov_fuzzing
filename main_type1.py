import sys
import logging
logging.basicConfig()
l = logging.getLogger("main_type1")
l.setLevel("INFO")

from farnsworth.models import Exploit, PovFuzzer1Job

import pov_fuzzing
import os

# make compilerex executable
import compilerex
bin_path = os.path.join(os.path.dirname(compilerex.__file__), "../bin")
for f in os.listdir(bin_path):
    os.chmod(os.path.join(bin_path, f), 0777)
    os.chmod(os.path.join(bin_path, f), 0777)

if len(sys.argv) != 2:
    print "Usage:", "job_id"

job_id = int(sys.argv[1])

job = PovFuzzer1Job.find(job_id)
if job is None:
    raise Exception("Couldn't find job %d", job_id)

cbn = job.cs.cbns_original[0]
crash = job.input_crash

crash_payload = str(crash.blob)
if len(crash_payload) > 20000:
    l.warning("payload has %d bytes, refusing to run", len(crash_payload))
    sys.exit(0)

l.info("Pov fuzzer 1 beginning to exploit crash %d for cbn %d", crash.id, cbn.id)
pov_fuzzer = pov_fuzzing.Type1CrashFuzzer(cbn.path, crash=crash_payload)

crashing_test = job.input_crash

if pov_fuzzer.exploitable():
    Exploit.create(cs=job.cs, job=job, pov_type='type1',
                   method="fuzzer",
                   c_code=pov_fuzzer.dump_c(),
                   blob=pov_fuzzer.dump_binary())
    l.info("crash was able to be exploited")
else:
    l.warning("Not exploitable")
