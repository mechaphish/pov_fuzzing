import os
import sys
import logging
logging.basicConfig()
l = logging.getLogger("main_type2")
l.setLevel("INFO")

from farnsworth.models import Exploit, PovFuzzer2Job, Test

import pov_fuzzing

# make compilerex executable
import compilerex
bin_path = os.path.join(os.path.dirname(compilerex.__file__), "../bin")
for f in os.listdir(bin_path):
    os.chmod(os.path.join(bin_path, f), 0777)
    os.chmod(os.path.join(bin_path, f), 0777)

if len(sys.argv) != 2:
    print "Usage:", "job_id"

job_id = int(sys.argv[1])

job = PovFuzzer2Job.find(job_id)
if job is None:
    raise Exception("Couldn't find job %d", job_id)

cbn = job.cs.cbns_original[0]
crash = job.input_crash

crash_payload = str(crash.blob)
if len(crash_payload) > 20000:
    l.warning("payload has %d bytes, refusing to run", len(crash_payload))
    sys.exit(0)

l.info("Pov fuzzer 2 beginning to exploit crash %d for cbn %d", crash.id, cbn.id)
pov_fuzzer = pov_fuzzing.Type2CrashFuzzer(cbn.path, crash=crash_payload)

if pov_fuzzer.exploitable():
    Exploit.create(cs=job.cs, job=job, pov_type='type1',
                   method="fuzzer",
                   c_code=pov_fuzzer.dump_c(),
                   blob=pov_fuzzer.dump_binary())
    l.info("crash was able to be exploited")
else:
    l.warning("Not exploitable")

if pov_fuzzer.dumpable():
    # FIXME: we probably want to store it in a different table with custom attrs
    Test.create(cs=job.cs, job=job, blob=pov_fuzzer.get_leaking_payload())
    l.info("possible leaking test was created")
else:
    l.warning("Couldn't even dump a leaking input")