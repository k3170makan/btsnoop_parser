## BTSnoop version 1.0 File Parser
Implementation of a btsnoop file parser in c.

## Usage
```
./btsnoop_parse.elf btsnoop_hci.log
```
Sample output:
```
>>./btsnoop_parse.elf ./btsnoop_sample.log 
btsnoop_header{
	- magic	=> 'b[0x62]  t[0x74]  s[0x73]  n[0x6e]  o[0x6f]  o[0x6f]  p[0x70]  [0x00]  
	- version	=> '0x01'
	- data link type => '0x3ea'
	}
(44)[0x2c] btsnoop_packet_record_t {
	* orignal length => 4
	* included length => 4
	* flags => 2
	* cummulative drops => 0
	* timestamp => Sun 1970-06-21 10:36:15 PDT
	* data
	[0x01] [0x03] [0x0c] [0x00] 

	}
...
        (3)[0x03] btsnoop_packet_record_t {
        * orignal length => 4
        * included length => 4
        * flags => 2
        * cummulative drops => 0
        * timestamp => Sun 1970-06-21 10:36:15 PDT
        * data
        [0x01] [0x05] [0x10] [0x00] 
                HCI CMD: [READ_RSSI ] {
                * opcode -> '0x1005'
                * opcode group   -> '0x04'
                * opcode command -> '0x05'
                * param_len -> '0x00' (0) bytes 


                }


        }

        (4)[0x04] btsnoop_packet_record_t {
        * orignal length => 14
        * included length => 14
        * flags => 3
        * cummulative drops => 0
        * timestamp => Sun 1970-06-21 10:36:15 PDT
        * data
        [0x04] [0x0e] [0x0b] [0x01] [0x05] [0x10] [0x00] [0x00] [0x04] [0x3c]
        [0x07] [0x00] [0x08] [0x00] 
                HCI EVENT: [COMMAND COMPLETE] {
                * event code -> '0x0e'
                * param_len -> '0x0b' (11) bytes 


                }


        }

```
## Building
```
make
```


