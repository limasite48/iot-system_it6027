### Available hardware
- 1 laptop running Windows (with a network card capable of broadcasting Wi-Fi)
- Some smartphones

### Preliminary description of the project implementation concept
To fulfill the requirement of building and testing a system for detecting insecure IoT devices within a network (a security system), the proposed approach is as follows:
- Build a true IoT network system, with the security system as a separate, independently operating sub-system within it.
- Because IoT networks are similar to the Internet, essentially consisting of multiple layers of networks stacked on top of each other, we will build the IoT network at the lowest layer (Edge Subnet - equivalent to a local Wi-Fi network below a router, with the members of the network being IoT devices).
- Regarding IoT devices in the network, it combines smartphones and Docker to emulate IoT devices. The system needs to treat all devices on the network as black-box (without distinguishing between real and simulated devices).

### System modules (sub-systems)
- 'net-infrastructure'
- 'net-core'
- 'net-sec'
- 'mock-object'

### Development pipeline
1. Develop the 'net-infrastructure' and 'net-core' modules. The foundational system was established, functioning as a genuine IoT network. Testing was conducted by connecting multiple smartphones (equipped with IP Webcam or equivalent IoT apps) to the system.
2. Develop the 'mock-object' module. In essence, this module consists of multiple small, independent Docker containers that simulate IoT devices (specifically those with security vulnerabilities). Testing involves verifying connectivity and scaling up the IoT system to handle a large number of devices.
3. Develop the 'net-sec' module. This module is designed to detect insecure IoT devices within the network. It must meet all project requirements and operate in accordance with industry standards.