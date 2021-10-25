#!/usr/bin/python3
# -*- coding: utf-8 -*-

import psutil
import time

if __name__ == "__main__":

    for i in range(1,100):
        CPU_usage = psutil.cpu_percent(interval=10)
        RAM_usage = psutil.virtual_memory().percent
        with open("CPU_RAM_usage.txt", "a") as f:
            f.write("CPU usage: %f\nRAM usage: %f\n" % (CPU_usage, RAM_usage))
