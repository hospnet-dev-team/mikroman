#!/usr/bin/python
# -*- coding: utf-8 -*-

# ping.py: ping tool for MikroWizard
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import asyncio
import platform

def ping_quality(time_ms):
    if time_ms is None:
        return "unreachable", "fa-solid fa-times-circle", "#dc3545"  # Red, times circle
    if time_ms <= 50:
        return "excellent", "fa-solid fa-check-circle", "#28a745"  # Green, check circle
    elif time_ms <= 100:
        return "good", "fa-solid fa-thumbs-up", "#80c29e"  # Light green, thumbs up
    elif time_ms <= 200:
        return "average", "fa-solid fa-exclamation-circle", "#ffc107"  # Yellow, exclamation circle
    else:
        return "poor", "fa-solid fa-times-circle", "#dc3545"  # Red, times circle

async def ping_host(host, timeout=1):
    system = platform.system()
    cmd = ["ping", "-c", "1", "-W", str(timeout), host]

    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    
    stdout, stderr = await process.communicate()
    result = stdout.decode().strip()
    error = stderr.decode().strip()

    # Extract time from output
    time_ms = None
    if "time=" in result:
        try:
            time_part = result.split("time=")[-1].split()[0]
            time_ms = float(time_part)
        except ValueError:
            pass

    quality, icon, color = ping_quality(time_ms)
    raw_response = result.split("\n")[0] if result else error.split("\n")[0]

    return {
        "host": host,
        "status": "success" if time_ms is not None else "failed",
        "time": time_ms if time_ms is not None else None,
        "ping_quality": quality,
        "icon": icon,
        "color": color,
        "raw_response": raw_response
    }

async def multi_ping_one_host(host, count=4, timeout=1):
    tasks = [ping_host(host, timeout) for _ in range(count)]
    results = await asyncio.gather(*tasks)

    successful_pings = [r["time"] for r in results if r["status"] == "success"]
    failed_pings = count - len(successful_pings)

    average_ping_time = round(sum(successful_pings) / len(successful_pings), 2) if successful_pings else None

    response = {
        "host": host,
        "count": count,
        "successful_pings": len(successful_pings),
        "failed_pings": failed_pings,
        "average_ping_time": average_ping_time,
        "results": results
    }

    return response

def get_ping_results(host, count=4, timeout=1):
    return asyncio.run(multi_ping_one_host(host, count, timeout))
