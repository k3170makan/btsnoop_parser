/** GNU Public by Keith Makan
*/
/**

	TODO:
		- finish the bt_packet_record_t->flags interpetation and printing
		- finish the bt_packet_record_t->timestamp printing, currently printing not enough or wrong
		- add hci packet decoding support
		- printout data fields for hci_packetw
		- printout uuids and devices found
		-
		- split off the files into seperate libraries etc
		- sync hci standards with this https://chromium.googlesource.com/aosp/platform/system/bt/+/master/stack/include/hcidefs.h
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>



/**
http://www.fte.com/webhelp/bpa600/Content/Technical_Information/BT_Snoop_File_Format.htm

*/

#define hexprint_int(number) (printf("0x%.2x 0x%.2x 0x%.2x 0x%.2x",\
	(unsigned int)number >> 3 & 0x000000ff,\
	(unsigned int)number >> 2 & 0x000000ff,\
	(unsigned int)number >> 1 & 0x000000ff,\
	(unsigned int)number & 0x000000ff))

#define BT_FILE_MAGIC_SZ sizeof(unsigned char)*8
#define BT_FILE_MAGIC_OFFSET 0
#define BT_FILE_VERSION_SZ sizeof(unsigned int)
#define BT_FILE_VERSION_OFFSET BT_FILE_MAGIC_OFFSET+BT_FILE_MAGIC_SZ
#define BT_FILE_DATALINK_TYPE_SZ sizeof(unsigned int)
#define BT_FILE_DATALINK_TYPE_OFFSET BT_FILE_VERSION_OFFSET+BT_FILE_VERSION_SZ
#define BT_FILE_HEADER_SZ BT_FILE_MAGIC_SZ+BT_FILE_VERSION_SZ+BT_FILE_DATALINK_TYPE_SZ
#define MAX_PACKET_LIST_SZ 1024
#define BT_PACKET_ORIGLEN_SZ sizeof(unsigned int)
#define BT_PACKET_INCLEN_SZ sizeof(unsigned int)
#define BT_PACKET_FLAGS_SZ sizeof(unsigned int)
#define BT_PACKET_DROPS_SZ sizeof(unsigned int)
#define BT_PACKET_TIMESTAMP_SZ sizeof(unsigned long)
#define BT_PACKET_RECORD_SZ sizeof(unsigned int)*4 + sizeof(unsigned long) //excludes the data field since thats only for the c library, in the actual file the unsigne int pointer takes up no size


#define MAX_PKT_DESCR_LEN 80
#define DATA_LINK_TYPE_RESERVED 1000
#define DATA_LINK_TYPE_UNENCAP 1001
#define DATA_LINK_TYPE_HCI_UART 1002
#define DATA_LINK_TYPE_HCI_BSCP 1003
#define DATA_LINK_TYPE_HCI_SERIAL 1004
#define DATA_LINK_TYPE_UNASSIGNED 1005

#define OGF(opcode) (uint16_t) (opcode >> 10) & 0x01FF
#define OCF(opcode) (uint16_t) opcode & 0x01FF

#define HCI_CMD_PKT 0x01
#define HCI_ASYNC_DATA_PKT 0x02
#define HCI_SYNC_DATA_PKT 0x03
#define HCI_EVENT_PKT 0x04
#define HCI_EXT_CMD_PKT 0x09 
#define HCI_VENDOR_CMD_PKT 0xff

#define HCI_EVENT_CODE_OFFSET 0x0
#define HCI_EVENT_CODE_SZ sizeof(uint16_t)
#define HCI_EVENT_PARAM_LEN_OFFSET sizeof(uint16_t)
#define HCI_EVENT_PARAM_LEN_SZ sizeof(uint16_t)
#define HCI_EVENT_PARAMS_OFFSET HCI_EVENT_PARAM_LEN_OFFSET + sizeof(uint16_t)

#define HCI_EVENT_INQUIRY_COMPLETE 0x01
#define HCI_EVENT_INQUIRY_RESULT 0x02
#define HCI_EVENT_CONNECTION_COMPLETE 0x03
#define HCI_EVENT_CONNECTION_REQUEST 0x04
#define HCI_EVENT_DISCONNECTION_COMPLETE 0x05
#define HCI_EVENT_AUTHENTICATION_COMPLETE 0x06
#define HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE 0x07
#define HCI_EVENT_ENCRYPTION_CHANGE 0x08
#define HCI_EVENT_LINK_KEY_CHANGE_COMPLETE 0x09
#define HCI_EVENT_MASTER_LINK_KEY_COMPLETE 0x0A
#define HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE 0x0B
#define HCI_EVENT_READ_REMOTE_VERSION_COMPLETE 0x0C
#define HCI_EVENT_QOS_SETUP_COMPLETE 0x0D
#define HCI_EVENT_COMMAND_COMPLETE 0x0E
#define HCI_EVENT_COMMAND_STATUS 0x0F
#define HCI_EVENT_HARDWARE_ERROR 0x10
#define HCI_EVENT_FLUSH_OCCURED 0x11
#define HCI_EVENT_ROLE_CHANGE 0x12
#define HCI_EVENT_NUMBER_OF_PACKETS 0x13
#define HCI_EVENT_MODE_CHANGE 0x14
#define HCI_EVENT_RETURN_LINK_KEYS 0x15
#define HCI_EVENT_PIN_CODE_REQUEST 0x16
#define HCI_EVENT_LINK_KEY_REQUEST 0x17
#define HCI_EVENT_LINK_KEY_NOTIFICATION 0x18
#define HCI_EVENT_LOOPBACK_COMMAND 0x19
#define HCI_EVENT_DATA_BUFFER_OVERFLOW 0x1A
#define HCI_EVENT_MAX_SLOTS_CHANGE 0x1B
#define HCI_EVENT_READ_CLOCK_OFFSET 0x1C
#define HCI_EVENT_CONNECTION_PACKET_TYPE_CHANGE 0x1D
#define HCI_EVENT_QOS_VIOLATION 0x1E
#define HCI_EVENT_PAGE_SCAN_MODE_CHANGE 0x1F
#define HCI_EVENT_PAGE_SCAN_REPETITION_CHANGE 0x20

#define HCI_EVENT_FLOW_SPECIFICATION_COMP_EVT 0x21
#define HCI_EVENT_INQUIRY_RSSI_RESULT_EVT 0x22
#define HCI_EVENT_READ_RMT_EXT_FEATURES_COMP_EVT 0x23
#define HCI_EVENT_ESCO_CONNECTION_COMP_EVT 0x2C
#define HCI_EVENT_ESCO_CONNECTION_CHANGED_EVT 0x2D
#define HCI_EVENT_SNIFF_SUB_RATE_EVT 0x2E
#define HCI_EVENT_EXTENDED_INQUIRY_RESULT_EVT 0x2F
#define HCI_EVENT_ENCRYPTION_KEY_REFRESH_COMP_EVT 0x30
#define HCI_EVENT_IO_CAPABILITY_REQUEST_EVT 0x31
#define HCI_EVENT_IO_CAPABILITY_RESPONSE_EVT 0x32
#define HCI_EVENT_USER_CONFIRMATION_REQUEST_EVT 0x33
#define HCI_EVENT_USER_PASSKEY_REQUEST_EVT 0x34
#define HCI_EVENT_REMOTE_OOB_DATA_REQUEST_EVT 0x35
#define HCI_EVENT_SIMPLE_PAIRING_COMPLETE_EVT 0x36
#define HCI_EVENT_LINK_SUPER_TOUT_CHANGED_EVT 0x38
#define HCI_EVENT_ENHANCED_FLUSH_COMPLETE_EVT 0x39
#define HCI_EVENT_USER_PASSKEY_NOTIFY_EVT 0x3B
#define HCI_EVENT_KEYPRESS_NOTIFY_EVT 0x3C
#define HCI_EVENT_RMT_HOST_SUP_FEAT_NOTIFY_EVT 0x3D
const char* event_descriptions[] = {
"INQUIRY COMPLETE",
"INQUIRY RESULT ",
"CONNECTION COMPLETE ",
"CONNECTION REQUEST",
"DISCONNECTION COMPLETE ",
"AUTHENTICATION COMPLETE",
"REMOTE NAME REQUEST COMPLETE ",
"ENCRYPTION CHANGE",
"LINK KEY CHANGE COMPLETE",
"MASTER LINK KEY COMPLETE ",
"READ REMOTE SUPPORTED FEATURES COMPLETE ",
"READ REMOTE VERSION COMPLETE ",
"QOS SETUP COMPLETE",
"COMMAND COMPLETE",
"COMMAND STATUS ",
"HARDWARE ERROR",
"FLUSH OCCURED ",
"ROLE CHANGE",
"NUMBER OF PACKETS",
"MODE CHANGE",
"RETURN LINK KEYS ",
"PIN CODE REQUEST ",
"LINK KEY REQUEST ",
"LINK KEY NOTIFICATION ",
"LOOPBACK COMMAND ",
"DATA BUFFER OVERFLOW ",
"MAX SLOTS CHANGE ",
"READ CLOCK OFFSET ",
"CONNECTION PACKET TYPE CHANGE ",
"QOS VIOLATION ",
"PAGE SCAN MODE CHANGE ",
"PAGE SCAN REPETITION CHANGE ",0};



#define HCI_CMD_OPCODE_OFFSET 0x0
#define HCI_CMD_OPCODE_SZ sizeof(uint16_t)
#define HCI_CMD_PARAM_LEN_OFFSET sizeof(uint16_t)
#define HCI_CMD_PARAM_LEN_SZ sizeof(uint16_t)
#define HCI_CMD_PARAMS_OFFSET HCI_CMD_PARAM_LEN_OFFSET + sizeof(uint16_t)

/*OGF 1*/
#define HCI_CMD_INQUIRY 0x01
#define HCI_CMD_INQUIRY_CANCEL 0x02
#define HCI_CMD_PERIODIC_INQUIRY_MODE 0x03
#define HCI_CMD_EXIT_PERIODIC_INQUIRY_MODE 0x04
#define HCI_CMD_CREATE_CONNECTION 0x05
#define HCI_CMD_DISCONNECT 0x06
#define HCI_CMD_ADD_SCO_CONNECTION 0x07
#define HCI_CMD_ACCEPT_CONNECTION_REQUEST 0x09
#define HCI_CMD_REJECT_CONNECTION_REQUEST 0x0A
#define HCI_CMD_LINK_KEY_REQUEST_REPLY 0x0B
#define HCI_CMD_LINK_KEY_REQUEST_NEGATIVE_REPLY 0x0C
#define HCI_CMD_PINCODE_REQUEST_REPLY 0x0D
#define HCI_CMD_PINCODE_REQUEST_NEGATIVE_REPLY 0x0E
#define HCI_CMD_CHANGE_CONNECTION_PACKET_TYPE 0x0F
#define HCI_CMD_AUTHENTICATION_REQUESTED 0x11
#define HCI_CMD_SET_CONNECTION_ENCRYPTION 0x13
#define HCI_CMD_CHANGE_CONNECTION_LINK_KEY 0x15
#define HCI_CMD_MASTER_LINK_KEY 0x17
#define HCI_CMD_REMOTE_NAME_REQUEST 0x19
#define HCI_CMD_READ_REMOTE_SUPPORTED_FEATURES 0x1B
#define HCI_CMD_READ_REMOTE_VERSION_INFORMATION 0x1D
#define HCI_CMD_READ_CLOCK_OFFSET 0x1F

//stolen from https://github.com/pauloborges/bluez/blob/master/lib/hci.h

typedef struct { uint8_t address[4] } btaddr_t;

typedef struct {
	uint8_t lap[3];
	uint8_t length;
	uint8_t num_rsp;

}hci_cmd_resp_inquiry;

typedef struct {
	uint8_t status;
	btaddr_t address;

}hci_cmd_resp_status_baddr;
typedef struct {
	uint16_t max_period;
	uint16_t min_period;
	uint8_t lap[3];
	uint8_t length;
	uint8_t num_rsp;

}hci_cmd_resp_periodic_inquiry;

typedef struct {
	btaddr_t address;
	uint16_t pkt_type;
	uint8_t pscan_rep_mode;
	uint8_t pscan_mode;
	uint16_t clock_offset;
	uint8_t role_switch;
	
}hci_cmd_resp_create_connection;

typedef struct {
	uint16_t handle;
	uint8_t reason;

}hci_cmd_resp_disconnect;

typedef struct {
	uint16_t handle;
	uint16_t pkt_type;

}hci_cmd_resp_add_sco;

typedef struct{
	btaddr_t address;

}hci_cmd_resp_create_connection_cancel;

typedef struct {
	btaddr_t address;
	uint8_t role;
}hci_cmd_resp_accept_connection_request;

typedef struct {
	btaddr_t address;
	uint8_t reason;
}hci_cmd_resp_rejected_connection_request;

typedef struct {
	btaddr_t address;
	uint8_t link_key[16];

}hci_cmd_resp_link_key_reply;

typedef struct {
	btaddr_t address;
	uint8_t pin_len;
	uint8_t pin_code;

}hci_cmd_resp_pin_code_reply;

typedef struct{
	uint16_t handle;

}hci_cmd_resp_set_connection_ptype;

typedef struct {
	uint16_t handle;
	uint8_t encrypt;	

} hci_cmd_resp_set_connection_encrypt;


typedef struct {
	uint16_t handle;
	
} hci_cmd_resp_change_connection_link_key;

typedef struct {
	uint8_t key_flag;	

} hci_cmd_resp_master_link_key;

typedef struct {
	btaddr_t address;
	uint8_t pscan_rep_mode;
	uint8_t pscan_mode;
	uint16_t clock_offset;

} hci_cmd_resp_remote_name_request;

typedef struct {
	uint16_t handle;	

} hci_cmd_resp_remote_name_request_cancel;

typedef struct {
	uint16_t handle;
} hci_cmd_resp_read_remote_features;

typedef struct {
	uint16_t handle;
	uint8_t page_num;
} hci_cmd_resp_read_remote_extended_features;

typedef struct{
	uint16_t handle;	
} hci_cmd_read_remote_version;

typedef struct {
	uint16_t handle;
} hci_cmd_read_clock_offset;


/*OGF 2*/
#define HCI_CMD_HOLD_MODE 0x001
#define HCI_CMD_SNIFF_MODE 0x003
#define HCI_CMD_EXIT_SNIFF_MODE 0x0004
#define HCI_CMD_PARK_MODE 0x0005
#define HCI_CMD_EXIT_PARK_MODE 0x0006
#define HCI_CMD_QOS_SETUP 0x0007
#define HCI_CMD_ROLE_DISCOVERY 0x0009
#define HCI_CMD_SWITCH_ROLE 0x000B
#define HCI_CMD_READ_LINK_POLICY_SETTINGS 0x000C
#define HCI_CMD_WRITE_LINK_POLICY_SETTINGS 0x000D

/*OGF 3*/
#define HCI_CMD_SET_EVENT_MASK 0x0001
#define HCI_CMD_RESET 0x0003
#define HCI_CMD_SET_EVENT_FILTER 0x0005
#define HCI_CMD_FLUSH 0x0008
#define HCI_CMD_READ_PIN_TYPE 0x0009
#define HCI_CMD_WRITE_PIN_TYPE 0x000A
#define HCI_CMD_CREATE_NEW_UNIT_KEY 0x000B
#define HCI_CMD_READ_STORED_LINK_KEY 0x000D
#define HCI_CMD_WRITE_STORED_LINK_KEY 0x0011
#define HCI_CMD_DELETE_STORED_LINK_KEY 0x0012
#define HCI_CMD_CHANGE_LOCAL_NAME 0x0013
#define HCI_CMD_READ_LOCAL_NAME 0x0014
#define HCI_CMD_READ_CONNECTION_ACCEPT_TIMEOUT 0x0015
#define HCI_CMD_WRITE_CONNECTION_ACCEPT_TIMEOUT 0x0016
#define HCI_CMD_READ_PAGE_TIMEOUT 0x0017
#define HCI_CMD_WRITE_PAGE_TIMEOUT 0x0018
#define HCI_CMD_READ_SCAN_ENABLE 0x0019
#define HCI_CMD_WRITE_SCAN_ENABLE 0x001A
#define HCI_CMD_READ_PAGE_SCAN_ACTIVITY 0x001B
#define HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY 0x001C
#define HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY 0x001D
#define HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY 0x001E
#define HCI_CMD_READ_AUTHENTICATION_ENABLE 0x001F
#define HCI_CMD_WRITE_AUTHENTICATION_ENABLE 0x0020
#define HCI_CMD_READ_ENCRYPTION_MODE 0x0021
#define HCI_CMD_WRITE_ENCRYPTION_MODE 0x0022
#define HCI_CMD_READ_DEVICE_CLASS 0x0023
#define HCI_CMD_WRITE_DEVICE_CLASS 0x0024
#define HCI_CMD_READ_VOICE_SETTING 0x0025
#define HCI_CMD_WRITE_VOICE_SETTING 0x0026
#define HCI_CMD_READ_AUTOMATIC_FLUSH_TIMEOUT 0x0027
#define HCI_CMD_WRITE_AUTOMATIC_FLUSH_TIMEOUT 0x0028
#define HCI_CMD_READ_NUM_BROADCAST_RETRANSMISSIONS 0x0029
#define HCI_CMD_WRITE_NUM_BROADCAST_RETRANSMISSIONS 0x002A
#define HCI_CMD_READ_HOLD_MODE_ACTIVITY 0x002B
#define HCI_CMD_WRITE_HOLD_MODE_ACTIVITY 0x002C
#define HCI_CMD_READ_TRANSMIT_POWER_LEVEL 0x002D
#define HCI_CMD_READ_SCO_FLOW_CONTROL_ENABLE 0x002E
#define HCI_CMD_WRITE_SCO_FLOW_CONTROL_ENABLE 0x002F
#define HCI_CMD_SET_HOST_CONTROLLER_TO_HOST_FLOW_CONTROL 0x0031
#define HCI_CMD_HOST_BUFFER_SIZE 0x0033
#define HCI_CMD_NUMBER_OF_COMPLETED_PACKETS 0x0035
#define HCI_CMD_READ_LINK_SUPERVISION_TIMEOUT 0x0036
#define HCI_CMD_WRITE_LINK_SUPERVISION_TIMEOUT 0x0037
#define HCI_CMD_READ_NUMBER_OF_SUPPORTED_IAC 0x0038
#define HCI_CMD_READ_CURRENT_IAC_LAP 0x0039
#define HCI_CMD_WRITE_CURRENT_IAC_LAP 0x003A
#define HCI_CMD_READ_PAGE_SCAN_PERIOD_MODE 0x003B
#define HCI_CMD_WRITE_PAGE_SCAN_PERIOD_MODE 0x003C
#define HCI_CMD_READ_PAGE_SCAN_MODE 0x003D
#define HCI_CMD_WRITE_PAGE_SCAN_MODE 0x003E
#define HCI_CMD_WRITE_SIMPLE_PARING_MODE 0x0056
#define HCI_CMD_WRITE_INQUIRY_MODE 0x0045
#define HCI_CMD_WRITE_PAGE_SCAN_TYPE 0x0047
/* OGF 4*/
#define HCI_CMD_READ_AUTHENTICATED_PAYLOAD_TIMEOUT 0x123
#define HCI_CMD_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT 0x124
#define HCI_CMD_READ_LOCAL_VERSION_INFORMATION 0x001
#define HCI_CMD_READ_LOCAL_SUPPORTED_COMMANDS	0x002
#define HCI_CMD_READ_LOCAL_SUPPORTED_FEATURES	0x004
#define HCI_CMD_READ_BD_ADDR 0x009
#define HCI_CMD_READ_RSSI 0x005


/*OGF group 8*/

#define HCI_CMD_LE_SET_EVENT_MASK 0x1
#define HCI_CMD_LE_READ_BUFFER_SIZE 0x2
#define HCI_CMD_LE_READ_LOCAL_SUPPORTED_FEATURES 0x3
#define HCI_CMD_LE_SET_RANDOM_ADDRES 0x5
#define HCI_CMD_LE_SET_ADVERTISING_PARAMETERS 0x6
#define HCI_CMD_LE_READ_ADVERTISING_CHANNEL_TX_POWER 0x7
#define HCI_CMD_LE_SET_ADVERTISING_DATA 0x8
#define HCI_CMD_LE_SET_SCAN_RESPONSE_DATA 0x9
#define HCI_CMD_LE_SET_ADVERTISE_ENABLE 0xA
#define HCI_CMD_LE_SET_SCAN_PARAMETERS 0xB
#define HCI_CMD_LE_SET_SCAN_ENABLE 0xC
#define HCI_CMD_LE_CREATE_CONNECTION 0xD
#define HCI_CMD_LE_CREATE_CONNECTION_CANCEL 0xE
#define HCI_CMD_LE_READ_WHITE_LIST_SIZE 0xF
#define HCI_CMD_LE_CLEAR_WHITE_LIST 0x10
#define HCI_CMD_LE_ADD_DEVICE_TO_WHITE_LIST 0x11
#define HCI_CMD_LE_REMOVE_DEVICE_FROM_WHITE_LIST 0x12
#define HCI_CMD_LE_CONNECTION_UPDATE 0x13
#define HCI_CMD_LE_SET_HOST_CHANNEL_CLASSIFICATION 0x14
#define HCI_CMD_LE_READ_CHANNEL_MAP 0x15
#define HCI_CMD_LE_READ_REMOTE_USED_FEATURES 0x16
#define HCI_CMD_LE_ENCRYPT 0x17
#define HCI_CMD_LE_RAND 0x18
#define HCI_CMD_LE_START_ENCRYPTION 0x19
#define HCI_CMD_LE_LONG_TERM_KEY_REQUESTED_REPLY 0x1A
#define HCI_CMD_LE_LONG_TERM_KEY_REQUESTED_NEGATIVE_REPLY 0x1B
#define HCI_CMD_LE_READ_SUPPORTED_STATES 0x1C
#define HCI_CMD_LE_RECEIVER_TEST 0x1D
#define HCI_CMD_LE_TRANSMITTER_TEST 0x1E
#define HCI_CMD_LE_TEST_END_COMMAND 0x1F
#define HCI_CMD_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY 0x20
#define HCI_CMD_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY 0x21
#define HCI_CMD_LE_SET_DATA_LENGTH 0x22
#define HCI_CMD_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH 0x23
#define HCI_CMD_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH 0x24
#define HCI_CMD_LE_READ_LOCAL_P256_PUBLIC_KEY 0x25
#define HCI_CMD_LE_GENERATE_DHKEY 0x26
#define HCI_CMD_LE_ADD_DEVICE_TO_RESOLVING_LIST 0x27
#define HCI_CMD_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST 0x28
#define HCI_CMD_LE_CLEAR_RESOLVING_LIST 0x29
#define HCI_CMD_LE_READ_RESOLVING_LIST_SIZE 0x2A
#define HCI_CMD_LE_READ_PEER_RESOLVABLE_ADDRESS 0x2B
#define HCI_CMD_LE_READ_LOCAL_RESOLVABLE_ADDRESS 0x2C
#define HCI_CMD_LE_SET_ADDRESS_RESOLUTION_ENABLE 0x2D
#define HCI_CMD_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT 0x2E
#define HCI_CMD_LE_READ_MAXIMUM_DATA_LENGTH 0x2F
#define HCI_CMD_LE_HOST_SUPPORTED 0x6D
#define HCI_CMD_WRITE_SECURE_CONNECTION_HOST_SUPPORT 0x7A

char *cmd_descriptions_group_4[] = {
"READ_AUTHENTICATED_PAYLOAD_TIMEOUT",
"WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT",
"READ_LOCAL_VERSION_INFORMATION",
"READ_LOCAL_SUPPORTED_COMMANDS",
"READ_LOCAL_SUPPORTED_FEATURES",
"READ_BD_ADDR ",
"READ_RSSI ",0};




const char *cmd_descriptions_group_1[] = {
"INQUIRY",
"INQUIRY CANCEL",
"PERIODIC INQUIRY MODE ",
"EXIT PERIODIC INQUIRY MODE ",
"CREATE CONNECTION",
"DISCONNECT",
"ADD SCO CONNECTION",
"ACCEPT CONNECTION REQUEST",
"REJECT CONNECTION REQUEST",
"LINK KEY REQUEST REPLY",
"LINK KEY REQUEST NEGATIVE REPLY",
"PINCODE REQUEST REPLY",
"PINCODE REQUEST NEGATIVE REPLY",
"CHANGE CONNECTION PACKET TYPE",
"AUTHENTICATION REQUESTED ",
"SET CONNECTION ENCRYPTION",
"CHANGE CONNECTION LINK KEY",
"MASTER LINK KEY",
"REMOTE NAME REQUEST",
"READ REMOTE SUPPORTED FEATURES",
"READ REMOTE VERSION INFORMATION",
"READ CLOCK OFFSET",0 };

char *cmd_descriptions_group_2[]= {
"HOLD MODE",
"SNIFF MODE",
"EXIT SNIFF MODE",
"PARK MODE",
"EXIT PARK MODE",
"QOS SETUP",
"ROLE DISCOVERY",
"SWITCH ROLE",
"READ LINK POLICY SETTINGS ",
"WRITE LINK POLICY SETTINGS",0};

char *cmd_descriptions_group_3[] = {
 "SET EVENT MASK", /*0x01*/
 "RESET", /*0x03*/
 "SET EVENT FILTER", /*0x05*/
 "FLUSH", /*0x08*/
 "READ PIN TYPE", /*0x09*/
 "WRITE PIN TYPE",
 "CREATE NEW UNIT KEY",
 "READ STORED LINK KEY",
 "WRITE STORED LINK KEY",
 "DELETE STORED LINK KEY",
 "CHANGE LOCAL NAME",
 "READ LOCAL NAME",
 "READ CONNECTION ACCEPT TIMEOUT",
 "WRITE CONNECTION ACCEPT TIMEOUT",
 "READ PAGE TIMEOUT",
 "WRITE PAGE TIMEOUT",
 "READ SCAN ENABLE",
 "WRITE SCAN ENABLE",
 "READ PAGE SCAN ACTIVITY",
 "WRITE PAGE SCAN ACTIVITY",
 "READ INQUIRY SCAN ACTIVITY",
 "WRITE INQUIRY SCAN ACTIVITY",
 "READ AUTHENTICATION ENABLE",
 "WRITE AUTHENTICATION ENABLE",
 "READ ENCRYPTION MODE",
 "WRITE ENCRYPTION MODE",
 "READ DEVICE CLASS",
 "WRITE DEVICE CLASS",
 "READ VOICE SETTING",
 "WRITE VOICE SETTING",
 "READ AUTOMATIC FLUSH TIMEOUT",
 "WRITE AUTOMATIC FLUSH TIMEOUT",
 "READ NUM BROADCAST RETRANSMISSIONS",
 "WRITE NUM BROADCAST RETRANSMISSIONS",
 "READ HOLD MODE ACTIVITY",
 "WRITE HOLD MODE ACTIVITY",
 "READ TRANSMIT POWER LEVEL",
 "READ SCO FLOW CONTROL ENABLE",
 "WRITE SCO FLOW CONTROL ENABLE",
 "SET HOST CONTROLLER TO HOST FLOW CONTROL",
 "HOST BUFFER SIZE",
 "NUMBER OF COMPLETED PACKETS",
 "READ LINK SUPERVISION TIMEOUT",
 "WRITE LINK SUPERVISION TIMEOUT",
 "READ NUMBER OF SUPPORTED IAC",
 "READ CURRENT IAC LAP",
 "WRITE CURRENT IAC LAP",
 "READ PAGE SCAN PERIOD MODE",
 "WRITE PAGE SCAN PERIOD MODE",
 "READ PAGE SCAN MODE",
 "WRITE PAGE SCAN MODE",
 "WRITE SIMPLE PARING MODE",
 "LE HOST SUPPORTED","WRITE INQUIRY MODE","WRITE SECURE CONNECTIONS HOST SUPPORT","WRITE SIMPLE PARING MODE",0};

char *cmd_descriptions_group_8[] = {
"LE SET EVENT MASK",
"LE READ BUFFER SIZE",
"LE READ LOCAL SUPPORTED FEATURES",
"LE SET RANDOM ADDRES",
"LE SET ADVERTISING PARAMETERS",
"LE READ ADVERTISING CHANNEL TX POWER",
"LE SET ADVERTISING DATA",
"LE SET SCAN RESPONSE DATA",
"LE SET ADVERTISE ENABLE",
"LE SET SCAN PARAMETERS",
"LE SET SCAN ENABLE",
"LE CREATE CONNECTION",
"LE CREATE CONNECTION CANCEL",
"LE READ WHITE LIST SIZE",
"LE CLEAR WHITE LIST",
"LE ADD DEVICE TO WHITE LIST",
"LE REMOVE DEVICE FROM WHITE LIST",
"LE CONNECTION UPDATE",
"LE SET HOST CHANNEL CLASSIFICATION",
"LE READ CHANNEL MAP",
"LE READ REMOTE USED FEATURES",
"LE ENCRYPT",
"LE RAND",
"LE START ENCRYPTION",
"LE LONG TERM KEY REQUESTED REPLY",
"LE LONG TERM KEY REQUESTED NEGATIVE REPLY",
"LE READ SUPPORTED STATES",
"LE RECEIVER TEST",
"LE TRANSMITTER TEST",
"LE TEST END COMMAND",
"LE REMOTE CONNECTION PARAMETER REQUEST REPLY",
"LE REMOTE CONNECTION PARAMETER REQUEST NEGATIVE REPLY",
"LE SET DATA LENGTH",
"LE READ SUGGESTED DEFAULT DATA LENGTH",
"LE WRITE SUGGESTED DEFAULT DATA LENGTH",
"LE READ LOCAL P256 PUBLIC KEY",
"LE GENERATE DHKEY",
"LE ADD DEVICE TO RESOLVING LIST",
"LE REMOVE DEVICE FROM RESOLVING LIST",
"LE CLEAR RESOLVING LIST",
"LE READ RESOLVING LIST SIZE",
"LE READ PEER RESOLVABLE ADDRESS",
"LE READ LOCAL RESOLVABLE ADDRESS",
"LE SET ADDRESS RESOLUTION ENABLE",
"LE SET RESOLVABLE PRIVATE ADDRESS TIMEOUT",
"LE READ MAXIMUM DATA LENGTH",0};

#define HCI_ASYNC_HANDLE_OFFSET 0x0
#define HCI_ASYNC_HANDLE_SZ 12
#define HCI_ASYNC_PB_FLAG_OFFSET HCI_ASYNC_HANDLE_SZ
#define HCI_ASYNC_PB_FLAG_SZ sizeof(uint16_t)
#define HCI_ASYNC_BC_FLAG_OFFSET HCI_ASYNC_PB_FLAG_OFFSET + HCI_ASYNC_PB_FLAG_SZ
#define HCI_ASYNC_BC_FLAG_SZ sizeof(uint16_t)
#define HCI_EVENT_PARAMS HCI_EVENT_PARAM_LEN_OFFSET + sizeof(uint16_t)


typedef struct hci_pkt_cmd{
	uint16_t opcode;
	uint8_t param_len;
	uint8_t *params;

} hci_pkt_cmd_t;

typedef struct hci_pkt_event{
	uint16_t event_code;
	uint8_t param_len;
	/*uint16_t opcode;*/
	uint8_t *params;

} hci_pkt_event_t;

typedef struct hci_pkt_async{
	unsigned char handle[12];
	uint16_t pb_flag;
	uint16_t bc_flag;
	uint16_t *data_len;
	uint8_t *data;
} hci_pkt_async_t;

typedef struct hci_pkt {
	hci_pkt_cmd_t *cmd;
	hci_pkt_async_t* async;
	hci_pkt_event_t* event;
	char *descr;

} hci_pkt_t;

typedef struct hci_packet_list{
	struct hci_packet_list *prev;
	struct hci_packet_list *next;
	hci_pkt_t *packet;	

} hci_packet_list_t;

//not sure how these work
/**
typedef struct btsnoop_hci_extevent_packet_t{
	unsigned char packet_type; 
	
	unsigned char param_length;
	unsigned char params[0];  

} hci_extevent_packet_t; **/



//refernces
//http://dev.ti.com/tirex/content/simplelink_cc13x2_sdk_2_30_00_45/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html
//https://github.com/joekickass/python-btsnoop
typedef struct btsnoop_packet_record{
	unsigned int orig_length; //original length, represents the length of the entire packet in bytes or "octets" lol
	unsigned int incl_length; //included length, represents the length of the data field
	unsigned int flags; //flags
	unsigned int drops; //could have gone with cumm_drops as an alternative name, just saying I made a wise choice here!
	unsigned long timestamp;
	unsigned char *data; //data included in the packet
	
} btsnoop_packet_record_t;

typedef struct btsnoop_packet_list{
	struct btsnoop_packet_list *prev;
	struct btsnoop_packet_list *next;
	btsnoop_packet_record_t *record;
	hci_packet_list_t * _hci_packet_list;

} btsnoop_packet_list_t;

typedef struct btsnoop_header{
	unsigned char magic[8];
	unsigned int version;
	unsigned int datalink_type;	

} btsnoop_header_t;

typedef struct btsnoop_file {
	struct btsnoop_header* header; //header of the btsnoop flie
	struct btsnoop_packet_record* record; //pointer to n array of snoop file records
	size_t file_size;

} btsnoop_file_t;


btsnoop_header_t* open_hci_log(const char*);
FILE* show_header(FILE *);
btsnoop_header_t* init_bt_header(FILE *);
static void print_bt_header(btsnoop_header_t *);
static void print_btpacket_record(unsigned int, btsnoop_packet_record_t *);


//some constants for fseek and fread
/**
typedef struct hci_pkt_event{
	uint16_t event_code;
	uint8_t param_len;
	uint8_t *params;

} hci_pkt_event_t;


**/

int readseek_btpacket_record(FILE *,btsnoop_packet_record_t *);
int readseek_btpacket_origlength(FILE *,btsnoop_packet_record_t *);
int readseek_btpacket_inclength(FILE *,btsnoop_packet_record_t *);
int readseek_btpacket_flags(FILE *,btsnoop_packet_record_t *);
int readseek_btpacket_drops(FILE *,btsnoop_packet_record_t *);
int readseek_btpacket_timestamp(FILE *,btsnoop_packet_record_t *);
int readseek_btpacket_data(FILE *,btsnoop_packet_record_t *);
int readseek_btsnoop_version(FILE *,btsnoop_header_t *);
int readseek_btsnoop_magic(FILE *,btsnoop_header_t *);
int readseek_btsnoop_datalink_type(FILE *,btsnoop_header_t *);


void parse_hci_event(hci_pkt_t *pkt,btsnoop_packet_record_t *record){

	unsigned int _index = 0;
	size_t descr_size;

	//hci_pkt_event_t *_event_pkt = (hci_pkt_event_t *) malloc(sizeof(hci_pkt_event_t));
	//_event_pkt->event_code = (uint16_t) record->data[1] & 0xFFFF;
	//_event_pkt->param_len = record->data[2] & 0xFFFF;

	pkt->event = (hci_pkt_event_t *) malloc(sizeof(hci_pkt_event_t));
	pkt->event->event_code = (uint16_t) record->data[1] & 0xFFFF;
	pkt->event->param_len = record->data[2] & 0xFFFF;

	pkt->descr = (char *)malloc(sizeof(char)*MAX_PKT_DESCR_LEN);

	switch(pkt->event->event_code){
		case HCI_EVENT_INQUIRY_COMPLETE: pkt->descr = event_descriptions[0];break;
		case HCI_EVENT_INQUIRY_RESULT: pkt->descr = event_descriptions[1];break;
		case HCI_EVENT_CONNECTION_COMPLETE: pkt->descr = event_descriptions[2];break;
		case HCI_EVENT_CONNECTION_REQUEST: pkt->descr = event_descriptions[3];break;
		case HCI_EVENT_DISCONNECTION_COMPLETE: pkt->descr = event_descriptions[4];break;
		case HCI_EVENT_AUTHENTICATION_COMPLETE: pkt->descr = event_descriptions[5];break;
		case HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE: pkt->descr = event_descriptions[6];break;
		case HCI_EVENT_ENCRYPTION_CHANGE: pkt->descr = event_descriptions[7];break;
		case HCI_EVENT_LINK_KEY_CHANGE_COMPLETE: pkt->descr = event_descriptions[8];break;
		case HCI_EVENT_MASTER_LINK_KEY_COMPLETE : pkt->descr = event_descriptions[9];break;
		case HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE: pkt->descr = event_descriptions[10];break;
		case HCI_EVENT_READ_REMOTE_VERSION_COMPLETE: pkt->descr = event_descriptions[11];break;
		case HCI_EVENT_QOS_SETUP_COMPLETE: pkt->descr = event_descriptions[12];break;
		case HCI_EVENT_COMMAND_COMPLETE: pkt->descr = event_descriptions[13];break;
		case HCI_EVENT_COMMAND_STATUS: pkt->descr = event_descriptions[14];break;
		case HCI_EVENT_HARDWARE_ERROR: pkt->descr = event_descriptions[15];break;
		case HCI_EVENT_FLUSH_OCCURED: pkt->descr = event_descriptions[16];break;
		case HCI_EVENT_ROLE_CHANGE: pkt->descr = event_descriptions[17];break;
		case HCI_EVENT_NUMBER_OF_PACKETS: pkt->descr = event_descriptions[18];break;
		case HCI_EVENT_MODE_CHANGE: pkt->descr = event_descriptions[19];break;
		case HCI_EVENT_RETURN_LINK_KEYS: pkt->descr = event_descriptions[20];break;
		case HCI_EVENT_PIN_CODE_REQUEST: pkt->descr = event_descriptions[21];break;
		case HCI_EVENT_LINK_KEY_REQUEST: pkt->descr = event_descriptions[22];break;
		case HCI_EVENT_LINK_KEY_NOTIFICATION: pkt->descr = event_descriptions[23];break;
		case HCI_EVENT_LOOPBACK_COMMAND: pkt->descr = event_descriptions[24];break;
		case HCI_EVENT_DATA_BUFFER_OVERFLOW: pkt->descr = event_descriptions[25];break;
		case HCI_EVENT_MAX_SLOTS_CHANGE: pkt->descr = event_descriptions[26];break;
		case HCI_EVENT_READ_CLOCK_OFFSET: pkt->descr = event_descriptions[27];break;
		case HCI_EVENT_CONNECTION_PACKET_TYPE_CHANGE: pkt->descr = event_descriptions[28];break;
		case HCI_EVENT_QOS_VIOLATION: pkt->descr = event_descriptions[29];break;
		case HCI_EVENT_PAGE_SCAN_MODE_CHANGE: pkt->descr = event_descriptions[30];break;
		case HCI_EVENT_PAGE_SCAN_REPETITION_CHANGE: pkt->descr = event_descriptions[31];break;
		default:break;	
	}
	return;
}

void parse_hci_cmd_params(hci_pkt_t* pkt,btsnoop_packet_record_t* record){
	
	return;	
}
void parse_hci_cmd(hci_pkt_t *pkt,btsnoop_packet_record_t *record){
	unsigned int _index = 0;

	pkt->cmd = (hci_pkt_cmd_t *) malloc(sizeof(hci_pkt_cmd_t));
	pkt->descr = (char *)malloc(sizeof(char)*MAX_PKT_DESCR_LEN);

	pkt->cmd->opcode = ((uint16_t ) (record->data[2] << 8) | record->data[1])  & 0xFFFF ;
	pkt->cmd->param_len = (uint16_t) record->data[3] & 0xFFFF;	
	pkt->cmd->params = (uint8_t *) malloc(sizeof(uint8_t)*pkt->cmd->param_len);


	switch(OGF(pkt->cmd->opcode)){
		case 0x01:
			switch(OCF(pkt->cmd->opcode)){
				case HCI_CMD_INQUIRY:                         pkt->descr = cmd_descriptions_group_1[0];break;
				case HCI_CMD_INQUIRY_CANCEL:                  pkt->descr = cmd_descriptions_group_1[1];break;
				case HCI_CMD_PERIODIC_INQUIRY_MODE:           pkt->descr = cmd_descriptions_group_1[2];break;
				case HCI_CMD_EXIT_PERIODIC_INQUIRY_MODE:      pkt->descr = cmd_descriptions_group_1[3];break;
				case HCI_CMD_CREATE_CONNECTION:               pkt->descr = cmd_descriptions_group_1[4];break;
				case HCI_CMD_DISCONNECT:                      pkt->descr = cmd_descriptions_group_1[5];break;
				case HCI_CMD_ADD_SCO_CONNECTION:              pkt->descr = cmd_descriptions_group_1[6];break;
				case HCI_CMD_ACCEPT_CONNECTION_REQUEST:       pkt->descr = cmd_descriptions_group_1[7];break;
				case HCI_CMD_REJECT_CONNECTION_REQUEST:       pkt->descr = cmd_descriptions_group_1[8];break;
				case HCI_CMD_LINK_KEY_REQUEST_REPLY:          pkt->descr = cmd_descriptions_group_1[9];break;
				case HCI_CMD_LINK_KEY_REQUEST_NEGATIVE_REPLY: pkt->descr = cmd_descriptions_group_1[10];break;
				case HCI_CMD_PINCODE_REQUEST_REPLY:           pkt->descr = cmd_descriptions_group_1[11];break;
				case HCI_CMD_PINCODE_REQUEST_NEGATIVE_REPLY:  pkt->descr = cmd_descriptions_group_1[12];break;
				case HCI_CMD_CHANGE_CONNECTION_PACKET_TYPE:   pkt->descr = cmd_descriptions_group_1[13];break;
				case HCI_CMD_AUTHENTICATION_REQUESTED:        pkt->descr = cmd_descriptions_group_1[14];break;
				case HCI_CMD_SET_CONNECTION_ENCRYPTION:       pkt->descr = cmd_descriptions_group_1[15];break;
				case HCI_CMD_CHANGE_CONNECTION_LINK_KEY:      pkt->descr = cmd_descriptions_group_1[16];break;
				case HCI_CMD_MASTER_LINK_KEY:                 pkt->descr = cmd_descriptions_group_1[17];break;
				case HCI_CMD_REMOTE_NAME_REQUEST:             pkt->descr = cmd_descriptions_group_1[18];break;
				case HCI_CMD_READ_REMOTE_SUPPORTED_FEATURES:  pkt->descr = cmd_descriptions_group_1[19];break;
				case HCI_CMD_READ_REMOTE_VERSION_INFORMATION: pkt->descr = cmd_descriptions_group_1[20];break;
				case HCI_CMD_READ_CLOCK_OFFSET:               pkt->descr = cmd_descriptions_group_1[21];break;
				default: pkt->descr = "UKNOWN COMMAND";break;
			}break;

			case 0x02:
				switch(OCF(pkt->cmd->opcode)){
					case HCI_CMD_HOLD_MODE:                  pkt->descr =  cmd_descriptions_group_2[0];break;
 					case HCI_CMD_SNIFF_MODE:                 pkt->descr =  cmd_descriptions_group_2[1];break;
 					case HCI_CMD_EXIT_SNIFF_MODE:            pkt->descr =  cmd_descriptions_group_2[2];break;
 					case HCI_CMD_PARK_MODE:                  pkt->descr =  cmd_descriptions_group_2[3];break;
 					case HCI_CMD_EXIT_PARK_MODE:             pkt->descr =  cmd_descriptions_group_2[4];break;
 					case HCI_CMD_QOS_SETUP:                  pkt->descr =  cmd_descriptions_group_2[5];break;
 					case HCI_CMD_ROLE_DISCOVERY:             pkt->descr =  cmd_descriptions_group_2[6];break;
 					case HCI_CMD_SWITCH_ROLE:                pkt->descr =  cmd_descriptions_group_2[7];break;
 					case HCI_CMD_READ_LINK_POLICY_SETTINGS:  pkt->descr =  cmd_descriptions_group_2[8];break;
 					case HCI_CMD_WRITE_LINK_POLICY_SETTINGS: pkt->descr =  cmd_descriptions_group_2[9];break;
					default: pkt->descr = "UKNOWN COMMAND";break;
				};break;

			case 0x03:
				switch(OCF(pkt->cmd->opcode)){
					case HCI_CMD_SET_EVENT_MASK: pkt->descr =  cmd_descriptions_group_3[0];break;
					case HCI_CMD_RESET: pkt->descr =  cmd_descriptions_group_3[1];break;
					case HCI_CMD_SET_EVENT_FILTER: pkt->descr =  cmd_descriptions_group_3[2];break;
					case HCI_CMD_FLUSH:pkt->descr =  cmd_descriptions_group_3[3];break;
					case HCI_CMD_READ_PIN_TYPE:pkt->descr =  cmd_descriptions_group_3[4];break;
					case HCI_CMD_WRITE_PIN_TYPE:pkt->descr =  cmd_descriptions_group_3[5];break;
					case HCI_CMD_CREATE_NEW_UNIT_KEY:pkt->descr =  cmd_descriptions_group_3[6];break;
					case HCI_CMD_READ_STORED_LINK_KEY:pkt->descr =  cmd_descriptions_group_3[7];break;
					case HCI_CMD_WRITE_STORED_LINK_KEY:pkt->descr =  cmd_descriptions_group_3[8];break;
					case HCI_CMD_DELETE_STORED_LINK_KEY:pkt->descr =  cmd_descriptions_group_3[9];break;
					case HCI_CMD_CHANGE_LOCAL_NAME:pkt->descr =  cmd_descriptions_group_3[10];break;
					case HCI_CMD_READ_LOCAL_NAME:pkt->descr =  cmd_descriptions_group_3[11];break;
					case HCI_CMD_READ_CONNECTION_ACCEPT_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[12];break;
					case HCI_CMD_WRITE_CONNECTION_ACCEPT_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[13];break;
					case HCI_CMD_READ_PAGE_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[14];break;
					case HCI_CMD_WRITE_PAGE_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[15];break;
					case HCI_CMD_READ_SCAN_ENABLE:pkt->descr =  cmd_descriptions_group_3[16];break;
					case HCI_CMD_WRITE_SCAN_ENABLE:pkt->descr =  cmd_descriptions_group_3[17];break;
					case HCI_CMD_READ_PAGE_SCAN_ACTIVITY:pkt->descr =  cmd_descriptions_group_3[18];break;
					case HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY:pkt->descr =  cmd_descriptions_group_3[19];break;
					case HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY:pkt->descr =  cmd_descriptions_group_3[20];break;
					case HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY:pkt->descr =  cmd_descriptions_group_3[21];break;
					case HCI_CMD_READ_AUTHENTICATION_ENABLE:pkt->descr =  cmd_descriptions_group_3[22];break;
					case HCI_CMD_WRITE_AUTHENTICATION_ENABLE:pkt->descr =  cmd_descriptions_group_3[23];break;
					case HCI_CMD_READ_ENCRYPTION_MODE:pkt->descr =  cmd_descriptions_group_3[24];break;
					case HCI_CMD_WRITE_ENCRYPTION_MODE:pkt->descr =  cmd_descriptions_group_3[25];break;
					case HCI_CMD_READ_DEVICE_CLASS:pkt->descr =  cmd_descriptions_group_3[26];break;
					case HCI_CMD_WRITE_DEVICE_CLASS:pkt->descr =  cmd_descriptions_group_3[27];break;
					case HCI_CMD_READ_VOICE_SETTING:pkt->descr =  cmd_descriptions_group_3[28];break;
					case HCI_CMD_WRITE_VOICE_SETTING:pkt->descr =  cmd_descriptions_group_3[29];break;
					case HCI_CMD_READ_AUTOMATIC_FLUSH_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[30];break;
					case HCI_CMD_WRITE_AUTOMATIC_FLUSH_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[31];break;
					case HCI_CMD_READ_NUM_BROADCAST_RETRANSMISSIONS:pkt->descr =  cmd_descriptions_group_3[32];break;
					case HCI_CMD_WRITE_NUM_BROADCAST_RETRANSMISSIONS:pkt->descr =  cmd_descriptions_group_3[33];break;
					case HCI_CMD_READ_HOLD_MODE_ACTIVITY:pkt->descr =  cmd_descriptions_group_3[34];break;
					case HCI_CMD_WRITE_HOLD_MODE_ACTIVITY:pkt->descr =  cmd_descriptions_group_3[35];break;
					case HCI_CMD_READ_TRANSMIT_POWER_LEVEL:pkt->descr =  cmd_descriptions_group_3[36];break;
					case HCI_CMD_READ_SCO_FLOW_CONTROL_ENABLE:pkt->descr =  cmd_descriptions_group_3[37];break;
					case HCI_CMD_WRITE_SCO_FLOW_CONTROL_ENABLE:pkt->descr =  cmd_descriptions_group_3[38];break;
					case HCI_CMD_SET_HOST_CONTROLLER_TO_HOST_FLOW_CONTROL:pkt->descr =  cmd_descriptions_group_3[39];break;
					case HCI_CMD_HOST_BUFFER_SIZE:pkt->descr =  cmd_descriptions_group_3[40];break;
					case HCI_CMD_NUMBER_OF_COMPLETED_PACKETS:pkt->descr =  cmd_descriptions_group_3[41];break;
					case HCI_CMD_READ_LINK_SUPERVISION_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[42];break;
					case HCI_CMD_WRITE_LINK_SUPERVISION_TIMEOUT:pkt->descr =  cmd_descriptions_group_3[43];break;
					case HCI_CMD_READ_NUMBER_OF_SUPPORTED_IAC:pkt->descr =  cmd_descriptions_group_3[44];break;
					case HCI_CMD_READ_CURRENT_IAC_LAP:pkt->descr =  cmd_descriptions_group_3[45];break;
					case HCI_CMD_WRITE_CURRENT_IAC_LAP:pkt->descr =  cmd_descriptions_group_3[46];break;
					case HCI_CMD_READ_PAGE_SCAN_PERIOD_MODE:pkt->descr =  cmd_descriptions_group_3[47];break;
					case HCI_CMD_WRITE_PAGE_SCAN_PERIOD_MODE:pkt->descr =  cmd_descriptions_group_3[48];break;
					case HCI_CMD_READ_PAGE_SCAN_MODE:pkt->descr =  cmd_descriptions_group_3[49];break;
					case HCI_CMD_WRITE_PAGE_SCAN_MODE:pkt->descr =  cmd_descriptions_group_3[50];break;
					case HCI_CMD_WRITE_SIMPLE_PARING_MODE:pkt->descr =  cmd_descriptions_group_3[51];break;
					case HCI_CMD_LE_HOST_SUPPORTED: pkt->descr = cmd_descriptions_group_3[0x52];break;
					case HCI_CMD_WRITE_INQUIRY_MODE: pkt->descr = cmd_descriptions_group_3[0x53];break;
					case HCI_CMD_WRITE_SECURE_CONNECTION_HOST_SUPPORT: pkt->descr = cmd_descriptions_group_3[0x54];break;
					case HCI_CMD_WRITE_PAGE_SCAN_TYPE: pkt->descr = cmd_descriptions_group_3[0x55];break;
					default: pkt->descr = "UKNOWN COMMAND";break;
				};break;
			case 0x04:
				switch(OCF(pkt->cmd->opcode)){
					case HCI_CMD_READ_AUTHENTICATED_PAYLOAD_TIMEOUT: pkt->descr = cmd_descriptions_group_4[0];break;
					case HCI_CMD_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT:pkt->descr = cmd_descriptions_group_4[1];break;
					case HCI_CMD_READ_LOCAL_VERSION_INFORMATION:pkt->descr = cmd_descriptions_group_4[2];break;
					case HCI_CMD_READ_LOCAL_SUPPORTED_COMMANDS:pkt->descr = cmd_descriptions_group_4[3];break;
					case HCI_CMD_READ_LOCAL_SUPPORTED_FEATURES:pkt->descr = cmd_descriptions_group_4[4];break;
					case HCI_CMD_READ_BD_ADDR:pkt->descr = cmd_descriptions_group_4[5];break;
					case HCI_CMD_READ_RSSI:pkt->descr = cmd_descriptions_group_4[6];break;
					default: pkt->descr = "UKNOWN COMMAND";break;
				};break;
			case 0x05:
				switch(OCF(pkt->cmd->opcode)){
					default: pkt->descr = "UKNOWN COMMAND";break;
				};break;
			case 0x06:
				switch(OCF(pkt->cmd->opcode)){
					default: pkt->descr = "UKNOWN COMMAND";break;
				};break;
			case 0x07:
				switch(OCF(pkt->cmd->opcode)){
					default: pkt->descr = "UKNOWN COMMAND";break;
				};break;
			case 0x08:
				switch(OCF(pkt->cmd->opcode)){
					case HCI_CMD_LE_SET_EVENT_MASK : pkt->descr = cmd_descriptions_group_8[0x1];break;
					case HCI_CMD_LE_READ_BUFFER_SIZE : pkt->descr = cmd_descriptions_group_8[0x2];break;
					case HCI_CMD_LE_READ_LOCAL_SUPPORTED_FEATURES : pkt->descr = cmd_descriptions_group_8[0x3];break;
					case HCI_CMD_LE_SET_RANDOM_ADDRES : pkt->descr = cmd_descriptions_group_8[0x4];break;
					case HCI_CMD_LE_SET_ADVERTISING_PARAMETERS : pkt->descr = cmd_descriptions_group_8[0x5];break;
					case HCI_CMD_LE_READ_ADVERTISING_CHANNEL_TX_POWER : pkt->descr = cmd_descriptions_group_8[0x6];break;
					case HCI_CMD_LE_SET_ADVERTISING_DATA : pkt->descr = cmd_descriptions_group_8[0x7];break;
					case HCI_CMD_LE_SET_SCAN_RESPONSE_DATA : pkt->descr = cmd_descriptions_group_8[0x8];break;
					case HCI_CMD_LE_SET_ADVERTISE_ENABLE : pkt->descr = cmd_descriptions_group_8[0x9];break;
					case HCI_CMD_LE_SET_SCAN_PARAMETERS : pkt->descr = cmd_descriptions_group_8[0x9];break;
					case HCI_CMD_LE_SET_SCAN_ENABLE : pkt->descr = cmd_descriptions_group_8[0xA];break;
					case HCI_CMD_LE_CREATE_CONNECTION : pkt->descr = cmd_descriptions_group_8[0xB];break;
					case HCI_CMD_LE_CREATE_CONNECTION_CANCEL : pkt->descr = cmd_descriptions_group_8[0xC];break;
					case HCI_CMD_LE_READ_WHITE_LIST_SIZE : pkt->descr = cmd_descriptions_group_8[0xD];break;
					case HCI_CMD_LE_CLEAR_WHITE_LIST : pkt->descr = cmd_descriptions_group_8[0xE];break;
					case HCI_CMD_LE_ADD_DEVICE_TO_WHITE_LIST : pkt->descr = cmd_descriptions_group_8[0xF];break;
					case HCI_CMD_LE_REMOVE_DEVICE_FROM_WHITE_LIST : pkt->descr = cmd_descriptions_group_8[0xA];break;
					case HCI_CMD_LE_CONNECTION_UPDATE : pkt->descr = cmd_descriptions_group_8[0x10];break;
					case HCI_CMD_LE_SET_HOST_CHANNEL_CLASSIFICATION : pkt->descr = cmd_descriptions_group_8[0x11];break;
					case HCI_CMD_LE_READ_CHANNEL_MAP : pkt->descr = cmd_descriptions_group_8[0x12];break;
					case HCI_CMD_LE_READ_REMOTE_USED_FEATURES : pkt->descr = cmd_descriptions_group_8[0x13];break;
					case HCI_CMD_LE_ENCRYPT : pkt->descr = cmd_descriptions_group_8[0x14];break;
					case HCI_CMD_LE_RAND : pkt->descr = cmd_descriptions_group_8[0x15];break;
					case HCI_CMD_LE_START_ENCRYPTION : pkt->descr = cmd_descriptions_group_8[0x16];break;
					case HCI_CMD_LE_LONG_TERM_KEY_REQUESTED_REPLY : pkt->descr = cmd_descriptions_group_8[0x17];break;
					case HCI_CMD_LE_LONG_TERM_KEY_REQUESTED_NEGATIVE_REPLY : pkt->descr = cmd_descriptions_group_8[0x18];break;
					case HCI_CMD_LE_READ_SUPPORTED_STATES : pkt->descr = cmd_descriptions_group_8[0x19];break;
					case HCI_CMD_LE_RECEIVER_TEST : pkt->descr = cmd_descriptions_group_8[0x1A];break;
					case HCI_CMD_LE_TRANSMITTER_TEST : pkt->descr = cmd_descriptions_group_8[0x1B];break;
					case HCI_CMD_LE_TEST_END_COMMAND : pkt->descr = cmd_descriptions_group_8[0x1C];break;
					case HCI_CMD_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY : pkt->descr = cmd_descriptions_group_8[0x1D];break;
					case HCI_CMD_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY : pkt->descr = cmd_descriptions_group_8[0x1E];break;
					case HCI_CMD_LE_SET_DATA_LENGTH : pkt->descr = cmd_descriptions_group_8[0x1F];break;
					case HCI_CMD_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH : pkt->descr = cmd_descriptions_group_8[0x20];break;
					case HCI_CMD_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH : pkt->descr = cmd_descriptions_group_8[0x21];break;
					case HCI_CMD_LE_READ_LOCAL_P256_PUBLIC_KEY : pkt->descr = cmd_descriptions_group_8[0x22];break;
					case HCI_CMD_LE_GENERATE_DHKEY : pkt->descr = cmd_descriptions_group_8[0x23];break;
					case HCI_CMD_LE_ADD_DEVICE_TO_RESOLVING_LIST : pkt->descr = cmd_descriptions_group_8[0x24];break;
					case HCI_CMD_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST : pkt->descr = cmd_descriptions_group_8[0x25];break;
					case HCI_CMD_LE_CLEAR_RESOLVING_LIST : pkt->descr = cmd_descriptions_group_8[0x26];break;
					case HCI_CMD_LE_READ_RESOLVING_LIST_SIZE : pkt->descr = cmd_descriptions_group_8[0x27];break;
					case HCI_CMD_LE_READ_PEER_RESOLVABLE_ADDRESS : pkt->descr = cmd_descriptions_group_8[0x28];break;
					case HCI_CMD_LE_READ_LOCAL_RESOLVABLE_ADDRESS : pkt->descr = cmd_descriptions_group_8[0x29];break;
					case HCI_CMD_LE_SET_ADDRESS_RESOLUTION_ENABLE : pkt->descr = cmd_descriptions_group_8[0x2A];break;
					case HCI_CMD_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT: pkt->descr = cmd_descriptions_group_8[0x30];break;
					case HCI_CMD_LE_READ_MAXIMUM_DATA_LENGTH : pkt->descr = cmd_descriptions_group_8[0x31];break;
					default: pkt->descr = "UKNOWN COMMAND";break;

				};break;
			default: pkt->descr = "UKNOWN COMMAND" ;break;
	}	
	return pkt;
}
void parse_hci_async(hci_pkt_t *pkt,btsnoop_packet_record_t *record){
	return;
}
void parse_hci_vendorcmd(hci_pkt_t *pkt,btsnoop_packet_record_t *record){
	return;
}

void parse_hci(hci_pkt_t *pkt, btsnoop_packet_record_t* packet_record){

	uint8_t pkt_type = 0;
	pkt_type = (uint8_t) packet_record->data[0];

	switch(pkt_type){
			case HCI_CMD_PKT:  
					parse_hci_cmd(pkt, packet_record);break;
			case HCI_ASYNC_DATA_PKT:  
					parse_hci_async(pkt, packet_record);break;
			case HCI_EVENT_PKT:  
					parse_hci_event(pkt, packet_record);break;
			case HCI_EXT_CMD_PKT:  
					parse_hci_event(pkt, packet_record);break;
			case HCI_VENDOR_CMD_PKT:  
					parse_hci_event(pkt, packet_record);break;
					parse_hci_vendorcmd(pkt, packet_record);break;
			default: printf("[x] problem determining cmd type...\n");pkt = NULL ;break;
	}		
	return;
}


int readseek_btpacket_origlength(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;
	if (!bt_packet_record){
		return -1;
	}
	bytes_read = fread(&bt_packet_record->orig_length,1,sizeof(unsigned int),file);
	bt_packet_record->orig_length = ntohl(bt_packet_record->orig_length);
	if (bytes_read < 0){
		return -1;
	}
	return bytes_read;	
}

int readseek_btpacket_inclength(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;
	if (!bt_packet_record){
		return -1;
	}
	bytes_read = fread(&bt_packet_record->incl_length,1,sizeof(unsigned int),file);
	bt_packet_record->incl_length = ntohl(bt_packet_record->incl_length);
	if (bytes_read < 0){
		return -1;
	}
	return bytes_read;	
}

int readseek_btpacket_flags(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;
	if (!bt_packet_record){
		return -1;
	}
	bytes_read = fread(&bt_packet_record->flags,1,sizeof(unsigned int),file);
	bt_packet_record->flags = ntohl(bt_packet_record->flags);
	if (bytes_read < 0){
		return -1;
	}
	return bytes_read;	
}

int readseek_btpacket_drops(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;
	if (!bt_packet_record){
		return -1;
	}
	bytes_read = fread(&bt_packet_record->drops,1,BT_PACKET_DROPS_SZ,file);
	bt_packet_record->drops = ntohl(bt_packet_record->drops);
	if (bytes_read < 0){
		return -1;
	}
	return bytes_read;	
}

int readseek_btpacket_timestamp(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;

	if (!bt_packet_record){
		return -1;
	}

	bytes_read = fread(&bt_packet_record->timestamp,1,BT_PACKET_TIMESTAMP_SZ,file);
	bt_packet_record->timestamp = ntohl(bt_packet_record->timestamp);
	if (bytes_read < 0){
		return -1;
	}
	return bytes_read;	
}

int readseek_btpacket_data(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;
	
	if (!bt_packet_record){
		return -1;
	}

	if (bt_packet_record->incl_length >= 1024){
		return -1;
	}
	unsigned char *data = (unsigned char *) malloc(sizeof(unsigned char)*bt_packet_record->incl_length);
	if (!data){
		return -1;
	}
	bytes_read = fread(data,sizeof(unsigned char),bt_packet_record->incl_length,file);
	
	if (bytes_read < 0){
		return -1;
	}

	unsigned int index = 0;
	bt_packet_record->data = data;
	return bytes_read;	
}

int readseek_btpacket_record(FILE *file,btsnoop_packet_record_t *bt_packet_record){
	int bytes_read = 0;

	memset(bt_packet_record,0x0,sizeof(BT_PACKET_RECORD_SZ));
	bytes_read = readseek_btpacket_origlength(file,bt_packet_record);
	if (bytes_read < 0){
		printf("[x] problem reading original length value from file bytes_read => %d\n",bytes_read);
		return -1;
	}

	memset(&bt_packet_record->incl_length,0x0,BT_PACKET_INCLEN_SZ);
	bytes_read = readseek_btpacket_inclength(file,bt_packet_record);
	if (bytes_read < 0){
		printf("[x] problem reading included length from file\n");
		return -1;
	}


	memset(&bt_packet_record->flags,0x0,BT_PACKET_FLAGS_SZ);
	bytes_read = readseek_btpacket_flags(file,bt_packet_record);

	if (bytes_read < 0){
		printf("[x] problem reading flags from file\n");
		return -1;
	}

	memset(&bt_packet_record->drops,0x0,BT_PACKET_DROPS_SZ);
	bytes_read = readseek_btpacket_drops(file,bt_packet_record);
	if (bytes_read < 0){
		printf("[x] problem reading drops from file\n");
		return -1;
	}

	memset(&bt_packet_record->timestamp,0x0,BT_PACKET_TIMESTAMP_SZ);
	bytes_read = readseek_btpacket_timestamp(file,bt_packet_record);

	if (!bytes_read){
		printf("[x] problem reading timestamp from file\n");
		return -1;
	}
	bytes_read = readseek_btpacket_data(file,bt_packet_record);
	if (!bytes_read){
		printf("[x] problem reading timestamp from file\n");
		return -1;
	}
	
	
	return bytes_read;	
}
void print_btpacket_record_withhci(unsigned int offset,
		btsnoop_packet_record_t * _bt_packet, 
			hci_pkt_t * _hci_pkt){

		time_t raw_time;
		char timestamp_buf[80]; 
		struct tm ts;
		unsigned int data_index = 0;

		printf("\t(%d)[0x%.2x] btsnoop_packet_record_t {\n",offset,offset);
		printf("\t* orignal length => %d\n",_bt_packet->orig_length);
		printf("\t* included length => %d\n",_bt_packet->incl_length);
		printf("\t* flags => %d\n",_bt_packet->flags);
		printf("\t* cummulative drops => %d\n",_bt_packet->drops);

		raw_time = _bt_packet->timestamp;	
		ts = *localtime(&raw_time);
		strftime(timestamp_buf,sizeof(timestamp_buf),"%a %Y-%m-%d %H:%M:%S %Z", &ts);

		printf("\t* timestamp => %s\n",timestamp_buf);
		printf("\t* data\n");
		unsigned int line_index = 0;

		for (data_index = 0;
					data_index < _bt_packet->incl_length; 
						data_index++){

				if (line_index == 0){
					printf("\t[0x%0.2x] ",
						_bt_packet->data[data_index]);
				}
				else if (line_index > 8){	
					printf("[0x%0.2x]\n\t",
						_bt_packet->data[data_index]);
					line_index = 0;
				}
				else{
					printf("[0x%0.2x] ",
						_bt_packet->data[data_index]);
				}
				line_index++;
		}	
		printf("\n");
		print_hci_packet(_hci_pkt);
		printf("\t}\n\n");
}
void print_hci_packet(hci_pkt_t * _hci_pkt){

		if (!_hci_pkt){	
			printf("[x] got a null hci packet\n");
			return;
		}

		if(_hci_pkt->cmd){ 
			printf("\t\tHCI CMD: [%s] {\n",
				_hci_pkt->descr);				

			printf("\t\t* opcode -> '0x%.2x'\n",
				_hci_pkt->cmd->opcode);

			printf("\t\t* opcode group   -> '0x%.2x'\n",
				OGF(_hci_pkt->cmd->opcode));

			printf("\t\t* opcode command -> '0x%.2x'\n",
				OCF(_hci_pkt->cmd->opcode));

			printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
				_hci_pkt->cmd->param_len,
					_hci_pkt->cmd->param_len);

		}else if(_hci_pkt->event){
			printf("\t\tHCI EVENT: [%s] {\n",_hci_pkt->descr);				
			printf("\t\t* event code -> '0x%.2x'\n",
				_hci_pkt->event->event_code);
			printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
				_hci_pkt->event->param_len,
				_hci_pkt->event->param_len);

		}else if(_hci_pkt->async){
			printf("\t\tHCI ASYNC EVENT: [%s] {");				

		}
		printf("\n\t\t}\n");

}


void print_btpacket_record(unsigned int offset, btsnoop_packet_record_t * _bt_packet){

		time_t raw_time;
		char timestamp_buf[80]; 
		struct tm ts;
		unsigned int data_index = 0;
		if (!_bt_packet){	
			return;
		}

		printf("\t(%d)[0x%.2x] btsnoop_packet_record_t {\n",offset,offset);
		printf("\t* orignal length => %d\n",_bt_packet->orig_length);
		printf("\t* included length => %d\n",_bt_packet->incl_length);
		printf("\t* flags => %d\n",_bt_packet->flags);
		printf("\t* cummulative drops => %d\n",_bt_packet->drops);

		raw_time = _bt_packet->timestamp;	
		ts = *localtime(&raw_time);
		strftime(timestamp_buf,sizeof(timestamp_buf),"%a %Y-%m-%d %H:%M:%S %Z", &ts);

		printf("\t* timestamp => %s\n",timestamp_buf);
		printf("\t* data\n");
		unsigned int line_index = 0;

		for (data_index = 0; data_index < _bt_packet->incl_length; data_index++){
				if (line_index == 0){
					printf("\t\t[0x%0.2x] ",_bt_packet->data[data_index]);
				}
				else if (line_index > 8){	
					printf("[0x%0.2x]\n\t",_bt_packet->data[data_index]);
					line_index = 0;
				}
				else{
					printf("[0x%0.2x] ",_bt_packet->data[data_index]);
				}
				line_index++;
		}	
		
		printf("\n\n\t}\n\n");
}

hci_pkt_t* init_hci_packet(){
	
	hci_pkt_t * _hci_packet = (hci_pkt_t *) malloc(sizeof(hci_pkt_t));
	if (!_hci_packet){
		return NULL;
	}
	memset(_hci_packet,0x0,sizeof(hci_pkt_t));	
	return _hci_packet; 
}

hci_packet_list_t* init_hci_packetlist(){
	
	hci_packet_list_t * _hci_packet_list = (hci_packet_list_t *) malloc(sizeof(hci_packet_list_t));
	if (!_hci_packet_list){
		return NULL;
	}
	memset(_hci_packet_list,0x0,sizeof(hci_packet_list_t));	
	return _hci_packet_list; 
}
btsnoop_packet_list_t* init_btsnoop_packetlist(){
	
	btsnoop_packet_list_t * _bt_packet_list = (btsnoop_packet_list_t *) malloc(sizeof(btsnoop_packet_list_t));
	if (!_bt_packet_list){
		return NULL;
	}
	memset(_bt_packet_list,0x0,sizeof(btsnoop_packet_list_t));	
	return _bt_packet_list; 
}
btsnoop_packet_record_t* init_btsnoop_record(){

	btsnoop_packet_record_t *_bt_packet = (btsnoop_packet_record_t *) malloc(sizeof(btsnoop_packet_record_t));
	if (!_bt_packet){
		return NULL;
	}
	memset(_bt_packet,0x0,sizeof(btsnoop_packet_list_t));	

	return _bt_packet;

}
btsnoop_packet_list_t* get_bt_packets(const char *filename){

	
	FILE *file = fopen(filename,"r");

	if (!file){
		printf("[x] problem opening file\n");
		return NULL;
	}

	hci_packet_list_t * _hci_packet_list = init_hci_packetlist();
	if (!_hci_packet_list){
		return NULL;
	}
	hci_packet_list_t * _hci_prev_list = init_hci_packetlist();
	if (!_hci_prev_list){
		return NULL;
	}
	hci_packet_list_t *_hci_next_list = init_hci_packetlist();
	if (!_hci_next_list){
		return NULL;
	}
	hci_packet_list_t *_hci_cur_list = init_hci_packetlist();
	if (!_hci_cur_list){
		return NULL;

	}

	btsnoop_packet_list_t * _bt_packet_list = init_btsnoop_packetlist();
	if (!_bt_packet_list){
		return NULL;
	}
	btsnoop_packet_list_t *_bt_prev_list = init_btsnoop_record();
	if (!_bt_prev_list){
		return NULL;
	}
	btsnoop_packet_list_t *_bt_next_list = init_btsnoop_packetlist();
	if (!_bt_next_list){
		return NULL;
	}
	btsnoop_packet_list_t *_bt_cur_list = init_btsnoop_packetlist();
	if (!_bt_cur_list){
		return NULL;
	}

	_bt_packet_list->prev = NULL;
	_bt_packet_list->record = NULL;
	_bt_packet_list->next = _bt_cur_list;
	_bt_prev_list = _bt_packet_list;

	_hci_packet_list->prev = NULL;
	_hci_packet_list->packet = NULL;
	_hci_packet_list->next = _hci_cur_list;
	_hci_prev_list = _hci_packet_list;


	_bt_packet_list->_hci_packet_list = _hci_packet_list;

	ssize_t bytes_read; 
	unsigned int index = 0;
	char *cur_data;
	unsigned int data_index;
	btsnoop_packet_record_t *_bt_packet;
	hci_pkt_t *_hci_pkt;
	fseek(file,BT_FILE_HEADER_SZ,SEEK_SET); //reset pointer

	while (bytes_read != -1){
		_bt_packet = (btsnoop_packet_record_t *) malloc(sizeof(btsnoop_packet_record_t));
		_hci_pkt = (hci_pkt_t *) malloc(sizeof(hci_pkt_t));
		if (!_bt_packet){
			return NULL;
		}
			
		bytes_read = readseek_btpacket_record(file,_bt_packet);
		if (_bt_packet && _bt_packet->incl_length){
			index += 1;
			_bt_cur_list->record = _bt_packet;

			parse_hci(_hci_pkt,_bt_packet);

			_hci_cur_list->packet = _hci_pkt;

			_hci_cur_list->prev = _hci_prev_list; 
			_bt_cur_list->prev = _bt_prev_list;	

			//get previous nodes
			btsnoop_packet_list_t *__bt_cur_prev = _bt_cur_list->prev;
			hci_packet_list_t *__hci_cur_prev = _hci_cur_list->prev;

			if (index != 0){
				//assign next pointers
				__bt_cur_prev->next = _bt_cur_list;
				__hci_cur_prev->next = _hci_cur_list;				
				//assign back pointers	
				_bt_prev_list = _bt_cur_list;
				_hci_prev_list = _hci_cur_list;

			}	

			_bt_cur_list->next = (btsnoop_packet_list_t *) malloc(sizeof(btsnoop_packet_list_t));
			_hci_prev_list->next = (hci_packet_list_t *) malloc(sizeof(hci_packet_list_t)); 

			//move up list
			_bt_cur_list = _bt_cur_list->next;
			_hci_cur_list = _hci_cur_list->next;

		}
	}
	return _bt_packet_list;
}


int readseek_btsnoop_magic(FILE *file,btsnoop_header_t *bt_file_header){
	int bytes_read = 0;

	bytes_read = fread(&bt_file_header->magic,BT_FILE_MAGIC_SZ,1,file);
	if (!bytes_read){
		printf("[x] problem reading magic value from file\n");
		return -1;
	}
	return bytes_read;	
}

int readseek_btsnoop_version(FILE *file,btsnoop_header_t *bt_file_header){
	int bytes_read = 0;

	fseek(file,BT_FILE_VERSION_OFFSET,SEEK_SET); //put pointer back
	memset(&bt_file_header->version,0x0,BT_FILE_VERSION_SZ);
	bytes_read = fread(&bt_file_header->version,BT_FILE_VERSION_SZ,1,file);

	if (!bytes_read){
		printf("[x] problem reading magic value from file\n");
		return -1;
	}
	
	return bytes_read;	
}

int readseek_btsnoop_datalink_type(FILE *file,btsnoop_header_t *bt_file_header){
	int bytes_read = 0;
	fseek(file,BT_FILE_DATALINK_TYPE_OFFSET,SEEK_SET); //put pointer back
	memset(&bt_file_header->datalink_type,0x0,BT_FILE_DATALINK_TYPE_SZ);
	bytes_read = fread(&bt_file_header->datalink_type,BT_FILE_DATALINK_TYPE_SZ,1,file);
	if (!bytes_read){
		printf("[x] problem reading magic value from file\n");
		return -1;
	}
	return bytes_read;	
}

btsnoop_header_t* init_bt_header(FILE * file){

	
	btsnoop_header_t *bt_file_header;
	btsnoop_packet_record_t *bt_packet;
	btsnoop_file_t *bt_file;
	ssize_t bytes_read; 

	bt_file_header = (btsnoop_header_t *)       malloc(sizeof(btsnoop_header_t));
	bt_packet =		  (btsnoop_packet_record_t *)malloc(sizeof(btsnoop_packet_record_t));
	bt_file =		  (btsnoop_file_t*)            malloc(sizeof(btsnoop_file_t));

	bytes_read = readseek_btsnoop_magic(file,bt_file_header);
	if (bytes_read < 0){
		printf("[x] didn't read full magic value, bailing...\n");
		return NULL;
	}

	bytes_read = readseek_btsnoop_version(file,bt_file_header);
	if (bytes_read < 0){
		printf("[x] didn't read full version value, bailing...\n");
		return NULL;
	}

	bytes_read = readseek_btsnoop_datalink_type(file,bt_file_header);
	if (bytes_read < 0){
		printf("[x] didn't read full datalink_type, bailing...\n");
		return NULL;
	}
	
	return bt_file_header;
}

btsnoop_header_t* open_hci_log(const char* filename){
	FILE *fp = fopen(filename,"r");
	btsnoop_header_t *bt_header;	
	if (fp == NULL){
		printf("[x] problem opening snoop log '%s'\n",filename);
		return -1;
	}
	bt_header = init_bt_header(fp);
	if (!bt_header){
		printf("[x] problem reading header from file...\n");
		return NULL;
	}
	close(fp);
	return bt_header;
}

static void print_bt_header(btsnoop_header_t *header){
	if (!header){
		return;
	}	
	printf("btsnoop_header{\n\t- magic	=> '");
	unsigned int index = 0;
	for (index = 0;index < 8; index++){
		printf("%c[0x%0.2x]  ", header->magic[index],header->magic[index]);
	} 
	printf("\n");
	//gotta re-solve the byte order problem

	printf("\t- version	=> '0x%0.2x'\n",ntohl(header->version));
	printf("\t- data link type => '0x%0.2x'\n\t}\n",ntohl(header->datalink_type) & 0x0000ffff);
	return;	
}

int main(int argc, char **argv){

	//init_header(open_hci_file());
	FILE *fp;
	if (argc != 2){
		printf("Usage : ./%s [btnsoop log file] \n",argv[0]);
		return -1;
	}	

	btsnoop_header_t *bt_header = NULL;
	bt_header = open_hci_log(argv[1]);
	print_bt_header(bt_header);
	btsnoop_packet_list_t *_packet_list = get_bt_packets(argv[1]); 
	hci_packet_list_t* _hci_packet_list = (hci_packet_list_t *) _packet_list->_hci_packet_list;
	unsigned int index = 0;
	while (_packet_list != NULL){

			btsnoop_packet_record_t *_packet_record = (btsnoop_packet_record_t *) _packet_list->record;	
			hci_pkt_t * _hci_packet = _hci_packet_list->packet;
			if (_hci_packet){
				print_btpacket_record_withhci(index,_packet_record,_hci_packet);

			}else{

				print_btpacket_record(index,_packet_record);
			}

			_packet_list = _packet_list->next;
			_hci_packet_list = _hci_packet_list->next;

			index++;
	}
	return 0;
}


