#ifndef __VR_DPDK_N3K_FAKE_VR_OFFLOADS_H__
#define __VR_DPDK_N3K_FAKE_VR_OFFLOADS_H__

#include <stdint.h>

struct vr_nexthop;
struct vr_interface;

void vr_dpdk_n3k_test_reset_mirrors();

int
mock_vr_dpdk_n3k_offload_nexthop_insert(struct vr_nexthop *nh);

int
mock_vr_dpdk_n3k_offload_nexthop_init(uint32_t count);

void
mock_vr_dpdk_n3k_offload_nexthop_exit(void);

int
mock_vr_dpdk_n3k_offload_interface_init(uint32_t count);

void
mock_vr_dpdk_n3k_offload_interface_insert(struct vr_interface *vif);

void
mock_vr_dpdk_n3k_offload_interface_exit();

#endif /* __VR_DPDK_N3K_FAKE_VR_OFFLOADS_H__ */
