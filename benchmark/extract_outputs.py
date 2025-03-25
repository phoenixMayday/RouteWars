import re

def parse_perf_stat(file_path):
    data = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comment lines
            if not line or line.startswith('#') or 'Performance counter stats' in line:
                continue
            
            # Match metric and value
            match = re.match(r'^\s*([\d,]+)\s+([\w-]+)', line)
            if match:
                value = match.group(1).replace(',', '')
                metric = match.group(2)
                data[metric] = value
            else:
                # Match time elapsed line
                match = re.match(r'^\s*([\d.]+)\s+seconds time elapsed', line)
                if match:
                    data['time elapsed (s)'] = match.group(1)
    return data

def parse_dnsperf(file_path):
    data = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('[') or line.startswith('DNS Performance'):
                continue
            
            # Match Queries sent/completed/lost
            match = re.match(r'^\s*Queries (sent|completed|lost):\s+(\d+)', line)
            if match:
                metric = f"Queries {match.group(1)}"
                value = match.group(2).replace(',', '')
                data[metric] = value
                continue
                
            # Match Run time
            match = re.match(r'^\s*Run time \(s\):\s+([\d.]+)', line)
            if match:
                data['Run time (s)'] = match.group(1)
                continue
                
            # Match Queries per second
            match = re.match(r'^\s*Queries per second:\s+([\d.]+)', line)
            if match:
                data['Queries per second'] = match.group(1)
                continue
                
            # Match Average Latency with min/max
            match = re.match(r'^\s*Average Latency \(s\):\s+([\d.]+)\s+\(min ([\d.]+),\s+max ([\d.]+)\)', line)
            if match:
                data['Average Latency (s)'] = match.group(1)
                data['Min Latency (s)'] = match.group(2)
                data['Max Latency (s)'] = match.group(3)
                continue
                
            # Match Latency StdDev
            match = re.match(r'^\s*Latency StdDev \(s\):\s+([\d.]+)', line)
            if match:
                data['Latency StdDev (s)'] = match.group(1)
    return data

def write_csv(perf_data, dnsperf_data, output_file):
    with open(output_file, 'w') as f:
        # Write perf data numbers in order
        for metric in ['cycles', 'instructions', 'cache-references', 'cache-misses',
                     'branches', 'branch-misses', 'page-faults', 'context-switches',
                     'cpu-migrations', 'LLC-load-misses', 'time elapsed (s)']:
            if metric in perf_data:
                f.write(f"{perf_data[metric]}\n")
        
        # Empty line before dnsperf data
        f.write("\n")
        
        # Write dnsperf data numbers in order
        for metric in ['Queries sent', 'Queries completed', 'Queries lost',
                     'Run time (s)', 'Queries per second', 'Average Latency (s)',
                     'Min Latency (s)', 'Max Latency (s)', 'Latency StdDev (s)']:
            if metric in dnsperf_data:
                f.write(f"{dnsperf_data[metric]}\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python parse_results.py perf_stat_output.txt dnsperf_output.txt parsed_output.txt")
        sys.exit(1)
    
    perf_file = sys.argv[1]
    dnsperf_file = sys.argv[2]
    output_file = sys.argv[3]
    
    perf_data = parse_perf_stat(perf_file)
    dnsperf_data = parse_dnsperf(dnsperf_file)
    write_csv(perf_data, dnsperf_data, output_file)
    
    print(f"Results written to {output_file}")
