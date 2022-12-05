# How to install

* Linux/macOS

  Copy `lua/iperf3.lua` to `$HOME/.local/lib/wireshark/plugins/` .

* Windows

  Copy `lua/iperf3.lua` to `<HOME>\AppData\Roaming\Wireshark\plugins\` .

# Screenshots

See [screenshots/](screenshots/) .

# TCP reassembly

According to [Wireshark doc](https://wiki.wireshark.org/Lua/Dissectors#tcp-reassembly):

> You should not write a dissector for TCP payload if you cannot handle reassembly.

My iperf3 dissector does not handle TCP reassembly so it may not work if there are fragmented TCP packets.
