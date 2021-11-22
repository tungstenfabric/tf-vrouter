# Intel PAC N3000 Offload Module

This module adds support for Intel PAC N3000 board. It implements GOM (General Offload Module) API to introduce full hardware flow offload into the vRouter-DPDK.

## Building

The `enableN3K` option must be passed to vRouter's SConscript using `--add-opts=enableN3K` option to compile and link n3k-specific vRouter code. Without this option N3K PMD context will not be registered.
Additionally, the N3K PMD should be enabled, built and linked with the vRouter-DPDK binary.

## Running

The `--enable_n3k <phy repr name>` option, where `<phy repr name>` is the name of the port representor of a N3K physical port, must be passed via vRouter's CLI to start the PMD context, which enables N3K hardware offload and n3k-specific vif handling. vRouter will fail to start if this option is passed and N3K PMD context is not registered, or the port representor name is invalid, or the N3K port representor cannot be found.

Additional DPDK EAL options can be passed using `--eal <name> [<value>]` option, where `<name>` is valid DPDK EAL option name, and `<value>` is its value. vRouter will fail to start if this option is passed and N3K PMD context is not registered or `rte_eal_init` returned an error. It is used to start N3K vdev or to pass any EAL option not handled by vRouter-specific options.

Other options related to N3K PMD context:

* `--no_drop_offload`: Do not offload flows with action drop to N3K
* `--aging_lcore`: Enable N3000 aging lcore. Aging lcore is used to synchronize flow statistics information between N3K and vRouter Agent.
* `--whitelist <pci address>[,vdpa=1]`: Add pci address to a PCI whitelist. Add `,vdpa=1` after address to enable vDPA for specified N3K VF. Otherwise PCI passthru of VF to VM is expected. Equivalent to `--eal --pci-whitelist`.

An example of vRouter’s CLI with N3K-based flow offload enabled is shown below (specified in `/etc/contrail/common_vrouter.env` on vRouter host):

```
DPDK_COMMAND_ADDITIONAL_ARGS=--whitelist pci:<mgmt PF> --whitelist pci:<slowpath VF> --vdev net_n3k0,mgmt=<mgmt PF>,pf=<slowpath VF>,vfs=[1,2,3] --enable_n3k net_n3k0_phy0 --offloads --no_drop_offload --aging_lcore --whitelist <VFx>,vdpa=1
```

Where:
* `<mgmt PF>`: PCI address of N3K management PF,
* `<slowpath VF>`: PCI address of N3K slowpath VF,
* `<VFx>`: PCI address of N3K VF used in vDPA mode,
* `vfs=[1,2,3]`: List of VFs, for which port representors are created.
