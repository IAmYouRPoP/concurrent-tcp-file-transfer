#pragma once

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/sysinfo.h>
#include <thread>

struct MemoryInfo
{
    double total_memory;
    double free_memory;
};

class ServerInfo
{
public:
    //TODO: Vezi de ce nu merge bine
    static MemoryInfo get_memory_usage()
    {
        struct sysinfo memory_info;
        sysinfo(&memory_info);

        long long total_physical_memory = memory_info.totalram;
        total_physical_memory *= memory_info.mem_unit;

        long long free_physical_memory = memory_info.freeram;

        free_physical_memory *= memory_info.mem_unit;

        MemoryInfo m;
        m.total_memory
            = static_cast<double>(total_physical_memory) / (1024 * 1024 * 1024);
        m.free_memory
            = static_cast<double>(free_physical_memory) / (1024 * 1024 * 1024);

        return m;
    }

    //Reads the total and the busy CPU time (in "ticks") from /proc/stat
    static bool read_cpu_times(long long& active, long long& total)
    {
        std::ifstream fileStat("/proc/stat");
        std::string   line;
        std::getline(fileStat, line);
        std::istringstream iss(line);
        std::string        cpu;
        long long          user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
        if(!(iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice))
        {
            return false;
        }
        active = user + nice + system + irq + softirq + steal;
        total  = active + idle + iowait;
        return true;
    }

    //CPU use during the last 100 ms (the old version gave the average since the machine was started)
    static int8_t get_cpu_usage_percentage()
    {
        long long active_1, total_1, active_2, total_2;
        if(!read_cpu_times(active_1, total_1))
        {
            return -1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if(!read_cpu_times(active_2, total_2))
        {
            return -1;
        }
        long long total_delta = total_2 - total_1;
        if(total_delta <= 0)
        {
            return 0;
        }
        return static_cast<int8_t>(100.0 * static_cast<double>(active_2 - active_1) / static_cast<double>(total_delta));
    }

    static long get_system_uptime_seconds()
    {
        struct sysinfo info;
        sysinfo(&info);
        return info.uptime;
    }
};
