#include "qemu/osdep.h"
#include "monitor/hmp-target.h"
#include "monitor/monitor.h"

void hmp_info_dart(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "DART is not available in this QEMU\n");
}
