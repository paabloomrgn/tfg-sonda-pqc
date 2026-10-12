This project implements an IDS (Intrusion Detection System) for SCADA networks that use the Modbus TCP protocol.

To compile:
gcc -Wextra -std=gnu11 -Wall  -o analisisModbus  analisisModbus.c -lm -lpcap


Execution command:
./analisisModbus. -f file.pcap



