#include "qemu/osdep.h"
 #include "hw/usb/tcp-usb.h"
#include "hw/qdev-properties.h"
#include "hw/core/qdev-prop-internal.h"

 const QEnumLookup USBTCPRemoteConnType_lookup = {
    .array =
        (const char *const[]){
            [TCP_REMOTE_CONN_TYPE_UNIX] = "unix",
            [TCP_REMOTE_CONN_TYPE_IPV4] = "ipv4",
            [TCP_REMOTE_CONN_TYPE_IPV6] = "ipv6",
        },
    .size = TCP_REMOTE_CONN_TYPE__MAX,
};

 const PropertyInfo qdev_usb_tcp_remote_conn_type = {
    .type = "USBTCPRemoteConnType",
    .description = "unix/ipv4/ipv6",
    .enum_table = &USBTCPRemoteConnType_lookup,
    .get = qdev_propinfo_get_enum,
    .set = qdev_propinfo_set_enum,
    .set_default_value = qdev_propinfo_set_default_value_enum,
};
