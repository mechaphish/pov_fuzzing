import os
import sys
import logging
import tempfile
import subprocess

from farnsworth.models import ChallengeSetFielding, IDSRuleFielding, Exploit, PovFuzzer1Job, PovTestResult

import pov_fuzzing
import compilerex

logging.basicConfig()
l = logging.getLogger("main_type1")
l.setLevel("INFO")

# make compilerex executable
bin_path = os.path.join(os.path.dirname(compilerex.__file__), "../bin")
for f in os.listdir(bin_path):
    os.chmod(os.path.join(bin_path, f), 0777)
    os.chmod(os.path.join(bin_path, f), 0777)

# make fake_single executable
fakesingle_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bin/fakesingle")
os.chmod(fakesingle_path, 0777)


NUM_THROWS = 5


def _test_exploit(pov, binaries, ids_rules=None):
    f1 = tempfile.mktemp(suffix=".pov")
    with open(f1, "wb") as f:
        f.write(pov)
    os.chmod(f1, 0777)

    f2 = tempfile.mktemp(suffix=".rules")
    if ids_rules is not None:
        with open(f2, "wb") as f:
            f.write(ids_rules)

    if ids_rules is None:
        args = ["cb-test", "--negotiate"]
        args += ["--cb"]
        args += binaries
        args += ["--directory", ".", "--timeout", "3", "--should_core", "--xml", f1]
    else:
        args = ["cb-test-ids-pov"]
        args += ["--cb"]
        args += binaries
        args += ["--directory", ".", "--timeout", "10", "--should_core", "--xml", f1]
        args += ["--ids_rules", f2, "--enable_remote", "--remote_nodes", "localhost", "localhost", "localhost"]

    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    os.remove(f1)

    if ids_rules is not None:
        os.remove(f2)

    if any(line.startswith("not ok") for line in stdout.split("\n")):
        return False

    if any(line.startswith("ok - TYPE") for line in stdout.split("\n")):
        return True
    return False


def _get_pov_score(fuzzer):
    pov = fuzzer.dump_binary()
    binaries = fuzzer.binaries
    ids_rules = fuzzer.ids_rules
    return [_test_exploit(pov, binaries, ids_rules) for _ in range(NUM_THROWS)].count(True) / float(NUM_THROWS)

if len(sys.argv) != 2:
    print "Usage:", "job_id"

job_id = int(sys.argv[1])

job = PovFuzzer1Job.find(job_id)
if job is None:
    raise Exception("Couldn't find job %d", job_id)

cs_fielding_id = job.payload['target_cs_fld']
ids_fielding_id = job.payload['target_ids_fld']

# get the cbnp for the originals if there isn't a fielding id
if cs_fielding_id is None:
    ids_rules = None
    if job.cs.is_multi_cbn:
        cbnp = map(lambda c: c.path, job.cs.cbns_original)
    else:
        cbnp = job.cs.cbns_original[0].path
# otherwise get the cs's in the fielding
else:
    cbnp = map(lambda c: c.path, ChallengeSetFielding.get(id=cs_fielding_id).cbns)
    # if the ids_fielding id is not None get it
    ids_rules = None
    if ids_fielding_id is not None:
        ids_rules_obj = IDSRuleFielding.get(id=ids_fielding_id).ids_rule
        if ids_rules_obj is not None and ids_rules_obj.rules is not None and len(str(ids_rules_obj.rules).strip()) > 0:
            ids_rules = str(ids_rules_obj.rules)

crash = job.input_crash

crash_payload = str(crash.blob)
time_limit = job.limit_time-10

l.info("Pov fuzzer 1 beginning to exploit crash %d for challenge %s", crash.id, job.cs.name)
try:
    pov_fuzzer = pov_fuzzing.Type1CrashFuzzer(cbnp, crash=crash_payload, ids_rules=ids_rules, time_limit=time_limit)

    crashing_test = job.input_crash

    if pov_fuzzer.exploitable():
        e = Exploit.create(cs=job.cs, job=job, pov_type='type1',
                           method="fuzzer",
                           c_code=pov_fuzzer.dump_c(),
                           blob=pov_fuzzer.dump_binary(),
                           crash=crashing_test)
        e.reliability = _get_pov_score(pov_fuzzer)
        # store a low reliability for the targeted ones
        if cs_fielding_id is not None:
            # store the pov test results
            num_success = round(e.reliability*10)
            PovTestResult.create(exploit=e, cs_fielding_id=cs_fielding_id, ids_fielding_id=ids_fielding_id,
                                 num_success=num_success)

            e.reliability = 0.01 * e.reliability
        e.save()

        l.info("crash was able to be exploited")
    else:
        l.warning("Not exploitable")

except pov_fuzzing.CrashFuzzerException as e:
    l.warning(e.message)
