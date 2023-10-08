import re
import subprocess as sp

lines = sp.check_output(['showevtinfo', '-E']).decode('utf-8')
lines = lines.replace('\t', ' ').split('\n')

re_cycles = re.compile(r"::UNHALTED_CORE_CYCLES$")
re_instr = re.compile(r"::INSTRUCTIONS_RETIRED")
re_fp = re.compile(r"FP_.*(INSTR|ARITH).*DOUBLE")
re_dram = re.compile(r"::OFFCORE_RESPONSE_0.*MISS.*(LOCAL|REMOTE)")
re_llc = re.compile(r"::(LLC|L3).*MISS")

perf_cycles = [m for m in lines if re.search(re_cycles, m)]
perf_instr = [m for m in lines if re.search(re_instr, m)]
perf_fp = [m for m in lines if re.search(re_fp, m)]
perf_dram = [m for m in lines if re.search(re_dram, m)]

if len(perf_dram) == 0:
    perf_dram = [m for m in lines if re.search(re_llc, m)]

perf_counters = list()


def add_perf_counters(perf_list):
    for item in perf_list:
        elems = item.split()
        if len(elems) > 2:
            expr = f"cpu/config={elems[0]},\
                    config1={elems[1]},name={elems[2]}/".replace(" ", "")
            perf_counters.append(
                    {'name': elems[2], 'expression': expr}
            )
        else:
            # expr = f"{elems[0].replace('0x', 'r')}".replace(" ", "")
            expr = f"cpu/config={elems[0]},\
                    name={elems[1]}/".replace(" ", "")
            perf_counters.append(
                    {'name': elems[1], 'expression': expr}
            )


add_perf_counters(perf_cycles)
add_perf_counters(perf_instr)
add_perf_counters(perf_fp)
add_perf_counters(perf_dram)

print("name,expression")
for elem in perf_counters:
    print(elem['name'] + "," + elem['expression'])
