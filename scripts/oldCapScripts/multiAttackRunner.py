import subprocess
import time

# RUN THIS AS SUDO

# The list of commands that IP Addrs will be appended to
attackCommands = [
    # ("python3 HTTPRequest.py ", "HTTP_Request")                # HTTP Request
    ('nmap -sX -p 1-100 ', 'XMAS_Flood'),
    ('hping3 -S -c 100 -p 443 ', 'TCP_SYN_Flood'),
    ('hping3 --udp -c 100 -p 53 ', 'UDP_Flood'),
    ('hping3 -S -c 100 -p 80 ', 'HTTP_Flood'),
]

ipAddrs = [
    ('192.168.1.200', 'okpVacc'),  # Need to redo!
    ('192.168.1.172', 'phillipsHub'),
    ('192.168.1.170', 'roborockVacc'),
    ('192.168.1.196', 'nestCam'),
    ('192.168.1.102', 'googleNestMini'),
    ('192.168.1.103', 'amazonAlexa'),
    ('192.168.1.175', 'longPlus-Cam'),
    ('192.168.1.104', 'kasaSmartPlug'),
    # ("192.168.1.", "GosungLight")
    # ("192.168.1.", "SmartPTZ")
    # ("192.168.1.", "QuickSetSmartLock")
    # ("192.168.1.", "RingDoorbell")
]

# The duration to collect packets (8 hours)
capture_duration = 8 * 60 * 60
# Safe period to stop attacks before the capture ends
safe_period = 15 * 60


def run_command(command):
    subprocess.run(command, shell=True)


# Function to schedule attacks within the allowed timeframe (8 hours minus the last 15 minutes)
def schedule_attacks(ipAddr, attackCommands, allowed_duration):
    # Start time of capture
    start_time = time.time()

    # Log file path
    log_path = f'./AttackCaps/{ipAddr[1]}_Multi.txt'

    # Open log file for writing timestamps
    with open(log_path, 'w') as log_file:
        total_attacks = len(attackCommands) * 3
        interval = allowed_duration / total_attacks
        end_time = start_time + allowed_duration

        for attackCommand in attackCommands:
            for i in range(3):  # Run each attack 3 times
                current_time = time.time()
                if current_time + interval < end_time:
                    # Execute attack
                    run_command(f'{attackCommand[0]}{ipAddr[0]}')
                    # Write timestamps to log
                    time_since_start = current_time - start_time
                    log_file.write(
                        f'Attack: {attackCommand[1]}, Attempt: {i + 1}, Unix Time: {current_time}, Time Since Start: {time_since_start}\n'
                    )
                    # Wait for the next attack
                    time.sleep(interval)
                else:
                    break


# Iterate through the list of devices
for ipAddr in ipAddrs:
    print(f'Capture started on {ipAddr[1]}')

    # Start tcpdump and collect packets
    tcpdump_process = subprocess.Popen(
        ['tcpdump', '-w', rf'./AttackCaps/{ipAddr[1]}_Multi.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Run attacks in the allowed timeframe (8 hours minus the last 15 minutes)
    schedule_attacks(ipAddr, attackCommands, capture_duration - safe_period)

    # Allow the capture to run the full 8 hours
    time.sleep(safe_period)

    # Terminate the tcpdump process
    tcpdump_process.terminate()

    print(f'Capture and attacks done on {ipAddr[1]}')
