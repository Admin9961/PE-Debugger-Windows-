import ctypes
import os
import datetime
import subprocess
import time
import win32api
import win32con
import logging
import threading
import signal
import psutil

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_process_id(process_name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            return process.info['pid']
    return -1

def is_process_running(process_id):
    return psutil.pid_exists(process_id)

def read_process_memory(process_handle, address, size):
    try:
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ctypes.windll.kernel32.ReadProcessMemory(
            int(process_handle),
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        return buffer.raw[:bytes_read.value]
    except Exception as e:
        return f"Error reading process memory: {str(e)}"

def dump_process_memory(process_id, dump_file_path):
    process_handle = None
    try:
        if process_id == -1:
            raise ValueError("Process not found")

        if not is_process_running(process_id):
            raise ValueError("Process is not currently running")

        process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            raise Exception(f"Failed to open process {process_id}")

        process_info = psutil.Process(process_id)

        with open(dump_file_path, 'wb') as dump_file:
            for chunk_start in range(0, process_info.memory_info().rss, 4096):
                chunk_data = read_process_memory(process_handle, chunk_start, 4096)
                dump_file.write(chunk_data)

        return {"status": "success", "message": f"Process memory dumped successfully to {dump_file_path}"}

    except ValueError as ve:
        return {"status": "error", "message": f"Error: {str(ve)}"}
    except FileNotFoundError as e:
        return {"status": "error", "message": f"Error: File not found - {str(e)}"}
    except OSError as e:
        return {"status": "error", "message": f"Error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

    finally:
        if process_handle:
            win32api.CloseHandle(process_handle)

def log_network_connections(process_id):
    try:
        process = psutil.Process(process_id)
        connections = process.connections()

        if connections:
            log_data = {"network_connections": []}

            for conn in connections:
                connection_info = {
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "protocol": conn.type,
                }
                log_data["network_connections"].append(connection_info)

            return log_data

        else:
            return {"network_connections": "No active network connections"}

    except Exception as e:
        return {"network_connections_error": str(e)}

def log_cpu_usage(process_id, cpu_log_file):
    try:
        while is_process_running(process_id):
            cpu_percent = psutil.Process(process_id).cpu_percent(interval=1)
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(cpu_log_file, 'a') as f:
                f.write(f"{current_time} - CPU Usage: {cpu_percent}%\n")

    except Exception as e:
        with open(cpu_log_file, 'a') as f:
            f.write(f"Error monitoring CPU usage: {str(e)}\n")

def extract_strings_from_memory_dump(dump_file_path):
    strings_output_file = 'strings_output.txt'
    try:
        strings_command_path = r'strings.exe'
        result = subprocess.run([strings_command_path, dump_file_path], capture_output=True, text=True, check=True)
        with open(strings_output_file, 'w') as f:
            f.write(result.stdout)
        return {"status": "success", "message": f"Strings extracted from memory dump and saved to {strings_output_file}"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": f"Error extracting strings: {e}"}

def run_sigcheck(executable_path):
    sigcheck_output_file = 'sigcheck.txt'
    sigcheck_command_path = r'sigcheck.exe'
    try:
        result = subprocess.run([sigcheck_command_path, executable_path], capture_output=True, text=True, check=True)
        with open(sigcheck_output_file, 'w') as f:
            f.write(result.stdout)
        return {"status": "success", "message": f"Sigcheck analysis performed and saved to {sigcheck_output_file}"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": f"Error running sigcheck: {e}\nCommand output:\n{e.output}"}

if not is_admin():
    print("Error: Run the script with elevated privileges.")
    exit(1)

custom_exe_path = input("Enter the full path of the target executable: ")

if not os.path.isfile(custom_exe_path):
    print("Error: Invalid executable path.")
    exit(1)

dump_file_path = f'dump_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.txt'
cpu_log_file = 'CPU.txt'
log_data = {"script_start_time": str(datetime.datetime.now()), "events": []}

process = subprocess.Popen(custom_exe_path, shell=True)

try:
    while True:
        process_id = get_process_id(os.path.basename(custom_exe_path))
        if process_id != -1:
            break
        time.sleep(2)

    result = dump_process_memory(process_id, dump_file_path)
    log_data["events"].append(result)

    result_network_connections = log_network_connections(process_id)
    log_data["events"].append(result_network_connections)

    cpu_thread = threading.Thread(target=log_cpu_usage, args=(process_id, cpu_log_file))
    cpu_thread.start()

    strings_extraction_result = extract_strings_from_memory_dump(dump_file_path)
    log_data["events"].append(strings_extraction_result)

    sigcheck_result = run_sigcheck(custom_exe_path)
    log_data["events"].append(sigcheck_result)

    logging.basicConfig(filename='script_log.json', level=logging.INFO)
    logging.info(str(log_data))
    print(str(log_data))

    terminate_flag = False

    def signal_handler(sig, frame):
        global terminate_flag
        print("\nReceived KeyboardInterrupt. Terminating debugging process.")
        process_id = get_process_id(os.path.basename(custom_exe_path))

        if process_id != -1:
            try:
                child_process = psutil.Process(process_id)
                for child in child_process.children(recursive=True):
                    child.terminate()
                child_process.terminate()
            except Exception as e:
                print(f"Error terminating process: {e}")

        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while not terminate_flag:
        time.sleep(1)

except KeyboardInterrupt:
    pass

finally:
    process.terminate()
    exit(0)