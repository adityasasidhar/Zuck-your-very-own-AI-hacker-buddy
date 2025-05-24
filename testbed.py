import platform


device_info = (
    f"System: {platform.system()}\n"
    f"Node: {platform.node()}\n"
    f"Release: {platform.release()}\n"
    f"Version: {platform.version()}\n"
    f"Machine: {platform.machine()}\n"
    f"Processor: {platform.processor()}"
)

print(f"let me tell you about this system:\n{device_info}")