/** GNU Public by Keith Makan
*/
/**

	TODO:
		- finish the bt_packet_record_t->flags interpetation and printing
		- finish the bt_packet_record_t->timestamp printing, currently printing not enough or wrong
		- add hci packet decoding support
		- printout uuids and devices found
		-
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


#define MAX_PKT_DESCR_LEN 80
#define DATA_LINK_TYPE_RESERVED 1000
#define DATA_LINK_TYPE_UNENCAP 1001
#define DATA_LINK_TYPE_HCI_UART 1002
#define DATA_LINK_TYPE_HCI_BSCP 1003
#define DATA_LINK_TYPE_HCI_SERIAL 1004
#define DATA_LINK_TYPE_UNASSIGNED 1005

#define OGF(opcode) (uint16_t) (opcode >> 9) & 0x1F
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

const char *cmd_descriptions[] = {
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


/*OGF 2*/
/*OGF 3*/

#define HCI_CMD_INQUIRY 0x01
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
void parse_hci_event(hci_pkt_t *pkt,btsnoop_packet_record_t *record){

	unsigned int _index = 0;

	hci_pkt_event_t *_hci_event = (hci_pkt_event_t *) malloc(sizeof(hci_pkt_event_t));
	_hci_event->event_code = (uint16_t) record->data[1] & 0xFFFF;
	_hci_event->param_len = record->data[2] & 0xFFFF;

	pkt->event = _hci_event;
	pkt->descr = (char *)malloc(sizeof(char)*MAX_PKT_DESCR_LEN);
	memset(&pkt->descr,0x0,sizeof(pkt->descr));

	size_t descr_size;
	//printf("\t[hci->event] event_code => '0x%.2x' : \n", _hci_event->event_code);

	switch(_hci_event->event_code){

		case HCI_EVENT_INQUIRY_COMPLETE: 
			descr_size = strlen(event_descriptions[HCI_EVENT_INQUIRY_COMPLETE-1]);
			strncpy(&pkt->descr,&event_descriptions[HCI_EVENT_INQUIRY_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_INQUIRY_RESULT: 
			descr_size = strlen(event_descriptions[HCI_EVENT_INQUIRY_RESULT-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_INQUIRY_RESULT-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_CONNECTION_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_CONNECTION_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_CONNECTION_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_CONNECTION_REQUEST:
			descr_size = strlen(event_descriptions[HCI_EVENT_CONNECTION_REQUEST-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_CONNECTION_REQUEST-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_DISCONNECTION_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_DISCONNECTION_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_DISCONNECTION_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_AUTHENTICATION_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_AUTHENTICATION_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_AUTHENTICATION_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break; 

		case HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_ENCRYPTION_CHANGE: 
			descr_size = strlen(event_descriptions[HCI_EVENT_ENCRYPTION_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_ENCRYPTION_CHANGE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_LINK_KEY_CHANGE_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_LINK_KEY_CHANGE_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_LINK_KEY_CHANGE_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_MASTER_LINK_KEY_COMPLETE: 
			descr_size = strlen(event_descriptions[HCI_EVENT_MASTER_LINK_KEY_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_MASTER_LINK_KEY_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_READ_REMOTE_VERSION_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_READ_REMOTE_VERSION_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_READ_REMOTE_VERSION_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;
	
		case HCI_EVENT_QOS_SETUP_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_QOS_SETUP_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_QOS_SETUP_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_COMMAND_COMPLETE:
			descr_size = strlen(event_descriptions[HCI_EVENT_CONNECTION_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_COMMAND_COMPLETE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_COMMAND_STATUS:
			descr_size = strlen(event_descriptions[HCI_EVENT_CONNECTION_COMPLETE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_COMMAND_STATUS-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_HARDWARE_ERROR:
			descr_size = strlen(event_descriptions[HCI_EVENT_HARDWARE_ERROR-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_HARDWARE_ERROR-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_FLUSH_OCCURED: 
			descr_size = strlen(event_descriptions[HCI_EVENT_FLUSH_OCCURED-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_FLUSH_OCCURED-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_ROLE_CHANGE: 
			descr_size = strlen(event_descriptions[HCI_EVENT_ROLE_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_ROLE_CHANGE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;
		case HCI_EVENT_NUMBER_OF_PACKETS: 
			descr_size = strlen(event_descriptions[HCI_EVENT_NUMBER_OF_PACKETS-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_NUMBER_OF_PACKETS-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;
	
		case HCI_EVENT_MODE_CHANGE:
			descr_size = strlen(event_descriptions[HCI_EVENT_MODE_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_MODE_CHANGE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;
	
		case HCI_EVENT_RETURN_LINK_KEYS:
			descr_size = strlen(event_descriptions[HCI_EVENT_RETURN_LINK_KEYS-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_RETURN_LINK_KEYS-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_PIN_CODE_REQUEST:
			descr_size = strlen(event_descriptions[HCI_EVENT_PIN_CODE_REQUEST-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_PIN_CODE_REQUEST-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_LINK_KEY_REQUEST :
			descr_size = strlen(event_descriptions[HCI_EVENT_LINK_KEY_REQUEST-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_LINK_KEY_REQUEST-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_LINK_KEY_NOTIFICATION :
			descr_size = strlen(event_descriptions[HCI_EVENT_LINK_KEY_NOTIFICATION-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_LINK_KEY_NOTIFICATION-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_LOOPBACK_COMMAND:
			descr_size = strlen(event_descriptions[HCI_EVENT_LOOPBACK_COMMAND-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_LOOPBACK_COMMAND-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_DATA_BUFFER_OVERFLOW: 
			descr_size = strlen(event_descriptions[HCI_EVENT_DATA_BUFFER_OVERFLOW-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_DATA_BUFFER_OVERFLOW-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break; 

		case HCI_EVENT_MAX_SLOTS_CHANGE:
			descr_size = strlen(event_descriptions[HCI_EVENT_MAX_SLOTS_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_MAX_SLOTS_CHANGE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_READ_CLOCK_OFFSET: 
			descr_size = strlen(event_descriptions[HCI_EVENT_READ_CLOCK_OFFSET-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_READ_CLOCK_OFFSET-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_CONNECTION_PACKET_TYPE_CHANGE:
			descr_size = strlen(event_descriptions[HCI_EVENT_CONNECTION_PACKET_TYPE_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_CONNECTION_PACKET_TYPE_CHANGE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_QOS_VIOLATION:
			descr_size = strlen(event_descriptions[HCI_EVENT_QOS_VIOLATION-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_QOS_VIOLATION-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_PAGE_SCAN_MODE_CHANGE:
			descr_size = strlen(event_descriptions[HCI_EVENT_PAGE_SCAN_MODE_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_PAGE_SCAN_MODE_CHANGE-1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		case HCI_EVENT_PAGE_SCAN_REPETITION_CHANGE:
			descr_size = strlen(event_descriptions[HCI_EVENT_PAGE_SCAN_REPETITION_CHANGE-1]);
			strncpy(&pkt->descr, &event_descriptions[HCI_EVENT_PAGE_SCAN_REPETITION_CHANGE+1], descr_size);
			//pkt->descr[descr_size] = '\0';
			break;

		default:break;	
	}

	//printf("\t[hci->event] param_len => '0x%.2x' (%d) bytes\n",_hci_event->param_len,_hci_event->param_len);
	return;
}

void parse_hci_cmd_params(hci_pkt_t* pkt,btsnoop_packet_record_t* record){
	
	return;	
}
void parse_hci_cmd(hci_pkt_t *pkt,btsnoop_packet_record_t *record){
	unsigned int _index = 0;

	hci_pkt_cmd_t *_cmd_pkt = (hci_pkt_cmd_t *) malloc(sizeof(hci_pkt_cmd_t));
	pkt->cmd = _cmd_pkt;

	size_t descr_size;
	pkt->descr = (char *)malloc(sizeof(char)*MAX_PKT_DESCR_LEN);

	_cmd_pkt->opcode = ((uint16_t ) (record->data[2] << 8) | record->data[1])  & 0xFFFF ;
	_cmd_pkt->param_len = (uint16_t) record->data[3] & 0xFFFF;	
	_cmd_pkt->params = (uint8_t *) malloc(sizeof(uint8_t)*_cmd_pkt->param_len);


	
	//if (_cmd_pkt->opcode != 0x03){ return; }

	//for (;_index < _cmd_pkt->param_len ;_index++){
	//		_cmd_pkt->params[_index] = record->data[3+_index];
	//}

	
	switch(OGF(_cmd_pkt->opcode)){
		case 0x01:
			switch(OCF(_cmd_pkt->opcode)){
				case HCI_CMD_INQUIRY:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_INQUIRY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_INQUIRY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_INQUIRY-1], descr_size);
					//pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_INQUIRY_CANCEL:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_INQUIRY_CANCEL-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_INQUIRY_CANCEL-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_INQUIRY_CANCEL-1], descr_size);
					//pkt->descr[descr_size] = '\0';
					break;
			
				case HCI_CMD_PERIODIC_INQUIRY_MODE: 
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_PERIODIC_INQUIRY_MODE-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_PERIODIC_INQUIRY_MODE-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_PERIODIC_INQUIRY_MODE-1], descr_size);
					//pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_EXIT_PERIODIC_INQUIRY_MODE:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_PERIODIC_INQUIRY_MODE-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_EXIT_PERIODIC_INQUIRY_MODE-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_EXIT_PERIODIC_INQUIRY_MODE-1], descr_size);
					//pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_CREATE_CONNECTION:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_CREATE_CONNECTION-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_CREATE_CONNECTION-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_CREATE_CONNECTION-1], descr_size);
					//pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_DISCONNECT:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_DISCONNECT-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_DISCONNECT-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_DISCONNECT-1], descr_size);
					//pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_ADD_SCO_CONNECTION: 
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_DISCONNECT-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_ADD_SCO_CONNECTION-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_ADD_SCO_CONNECTION-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_ACCEPT_CONNECTION_REQUEST:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_ACCEPT_CONNECTION_REQUEST-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_ACCEPT_CONNECTION_REQUEST-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_ACCEPT_CONNECTION_REQUEST-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_REJECT_CONNECTION_REQUEST:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_REJECT_CONNECTION_REQUEST-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_REJECT_CONNECTION_REQUEST-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_REJECT_CONNECTION_REQUEST-1], descr_size);
					//&&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_LINK_KEY_REQUEST_REPLY:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_LINK_KEY_REQUEST_REPLY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_LINK_KEY_REQUEST_REPLY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_LINK_KEY_REQUEST_REPLY-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_LINK_KEY_REQUEST_NEGATIVE_REPLY:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_LINK_KEY_REQUEST_NEGATIVE_REPLY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_LINK_KEY_REQUEST_NEGATIVE_REPLY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_LINK_KEY_REQUEST_NEGATIVE_REPLY-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_PINCODE_REQUEST_REPLY:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_PINCODE_REQUEST_REPLY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_PINCODE_REQUEST_REPLY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_PINCODE_REQUEST_REPLY-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_PINCODE_REQUEST_NEGATIVE_REPLY:

					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_PINCODE_REQUEST_NEGATIVE_REPLY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_PINCODE_REQUEST_NEGATIVE_REPLY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_PINCODE_REQUEST_NEGATIVE_REPLY-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_CHANGE_CONNECTION_PACKET_TYPE:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_CHANGE_CONNECTION_PACKET_TYPE-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_CHANGE_CONNECTION_PACKET_TYPE-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_CHANGE_CONNECTION_PACKET_TYPE-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_AUTHENTICATION_REQUESTED:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_AUTHENTICATION_REQUESTED-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_AUTHENTICATION_REQUESTED-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_AUTHENTICATION_REQUESTED-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_SET_CONNECTION_ENCRYPTION:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_SET_CONNECTION_ENCRYPTION-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_SET_CONNECTION_ENCRYPTION-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_SET_CONNECTION_ENCRYPTION-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_CHANGE_CONNECTION_LINK_KEY:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_CHANGE_CONNECTION_LINK_KEY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_CHANGE_CONNECTION_LINK_KEY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_CHANGE_CONNECTION_LINK_KEY-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_MASTER_LINK_KEY:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_MASTER_LINK_KEY-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_MASTER_LINK_KEY-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_MASTER_LINK_KEY-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_REMOTE_NAME_REQUEST:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_REMOTE_NAME_REQUEST-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_REMOTE_NAME_REQUEST-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_REMOTE_NAME_REQUEST-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_READ_REMOTE_SUPPORTED_FEATURES:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_READ_REMOTE_SUPPORTED_FEATURES-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_READ_REMOTE_SUPPORTED_FEATURES-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_READ_REMOTE_SUPPORTED_FEATURES-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_READ_REMOTE_VERSION_INFORMATION:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_READ_REMOTE_VERSION_INFORMATION-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_READ_REMOTE_VERSION_INFORMATION-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_READ_REMOTE_VERSION_INFORMATION-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;

				case HCI_CMD_READ_CLOCK_OFFSET:
					printf("[?] cmd %s\n",cmd_descriptions[HCI_CMD_READ_CLOCK_OFFSET-1]); 
					descr_size = strlen(cmd_descriptions[HCI_CMD_READ_CLOCK_OFFSET-1]); 
					strncpy(&pkt->descr, &cmd_descriptions[HCI_CMD_READ_CLOCK_OFFSET-1], descr_size);
					//&pkt->descr[descr_size] = '\0';
					break;
			}break;
	}	
	printf("\t\tHCI CMD: [%s] {\n",
				pkt->descr);				

	printf("\t\t* opcode -> '0x%.4x'\n",
		_cmd_pkt->opcode);

	printf("\t\t* opcode group   -> '0x%.2x'\n",
		OGF(_cmd_pkt->opcode));

	printf("\t\t* opcode command -> '0x%.2x'\n",
		OCF(_cmd_pkt->opcode));

	printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
		_cmd_pkt->param_len,
			_cmd_pkt->param_len);
	printf("\t\t}\n");
	
	return;
}
void parse_hci_async(hci_pkt_t *pkt,btsnoop_packet_record_t *record){
	return;
}
void parse_hci_vendorcmd(hci_pkt_t *pkt,btsnoop_packet_record_t *record){
	return;
}

void parse_hci(hci_pkt_t *pkt, btsnoop_packet_record_t* packet_record){

	//printf("[hci] parsing hci packet @ (%p)\n", &packet_record);

	uint8_t pkt_type = 0;
	pkt = (hci_pkt_t *) malloc(sizeof(hci_pkt_t));

	//if (!packet_record){ return ;}
	pkt_type = (uint8_t) packet_record->data[0];
	//printf("[*] parsing hci packet...\n");
	//print_btpacket_record(0,packet_record);
	
	//printf("\t[hci] packet type -> [0x%.2x]\n",pkt_type);

	switch(pkt_type){
			case HCI_CMD_PKT:  
					//printf(" HCI_CMD\n");	
					parse_hci_cmd(pkt,packet_record);break;
			case HCI_ASYNC_DATA_PKT:  
					//printf(" HCI_ASYNC_DATA\n");	
					parse_hci_async(pkt,packet_record);break;
			case HCI_EVENT_PKT:  
					//printf(" HCI_EVENT\n");	
					parse_hci_event(pkt,packet_record);break;
			case HCI_EXT_CMD_PKT:  
					//printf(" HCI_EXT_EVENT\n");	
					parse_hci_event(pkt,packet_record);break;
			case HCI_VENDOR_CMD_PKT:  
					//printf(" HCI_VENDOR_CMD\n");	
					parse_hci_event(pkt,packet_record);break;
					parse_hci_vendorcmd(pkt,packet_record);break;
			default: printf("[x] problem determining cmd type...\n") ;break;
	}		
	return;
}


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
	//printf("[*] orig_length -> %d\n",bt_packet_record->orig_length);
	if (bytes_read < 0){
		printf("[x] problem reading original length value from file bytes_read => %d\n",bytes_read);
		return -1;
	}

	memset(&bt_packet_record->incl_length,0x0,BT_PACKET_INCLEN_SZ);
	bytes_read = readseek_btpacket_inclength(file,bt_packet_record);
	//printf("[*] incl_length -> %d\n",bt_packet_record->incl_length);
	if (bytes_read < 0){
		printf("[x] problem reading included length from file\n");
		return -1;
	}


	memset(&bt_packet_record->flags,0x0,BT_PACKET_FLAGS_SZ);
	bytes_read = readseek_btpacket_flags(file,bt_packet_record);
	//printf("[*] flags -> %d\n",bt_packet_record->flags);

	if (bytes_read < 0){
		printf("[x] problem reading flags from file\n");
		return -1;
	}

	memset(&bt_packet_record->drops,0x0,BT_PACKET_DROPS_SZ);
	bytes_read = readseek_btpacket_drops(file,bt_packet_record);
	//printf("[*] drops -> %d\n",bt_packet_record->drops);
	if (bytes_read < 0){
		printf("[x] problem reading drops from file\n");
		return -1;
	}

	memset(&bt_packet_record->timestamp,0x0,BT_PACKET_TIMESTAMP_SZ);
	bytes_read = readseek_btpacket_timestamp(file,bt_packet_record);
	//printf("[*] timestamp -> %d\n",bt_packet_record->timestamp);

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
		//if (_bt_packet == NULL ||  _hci_pkt == NULL){	
		//	printf("[x] problem printing btpacket with hci (%d)\n",sizeof(_hci_pkt));
		//	return;
		//}
		//if(!(_bt_packet != NULL &&  _hci_pkt != NULL)){
		//	return;
		//}

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
		
		//print hci data
		hci_pkt_cmd_t *_cmd_pkt = (hci_pkt_cmd_t*) _hci_pkt->cmd;
		if(_cmd_pkt != NULL){ //gotta check for cmd sonner
			hci_pkt_cmd_t *_cmd_pkt = &_hci_pkt->cmd;

			printf("\t\tHCI CMD: [%s] {",
				_hci_pkt->descr);				

			printf("\t\t* opcode -> '0x%.4x'\n",
				_cmd_pkt->opcode);

			printf("\t\t* opcode group   -> '0x%.2x'\n",
				OGF(_cmd_pkt->opcode));

			printf("\t\t* opcode command -> '0x%.2x'\n",
				OCF(_cmd_pkt->opcode));

			printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
				_cmd_pkt->param_len,
					_cmd_pkt->param_len);

		}else if(_hci_pkt->event){
			hci_pkt_event_t *_event_pkt = &_hci_pkt->event;

			printf("\t\tHCI EVENT:%s {");				
			printf("\t\t* event code -> '0x%.4x'\n",
				_event_pkt->event_code);
			printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
				_event_pkt->param_len,
				_event_pkt->param_len);

		}else if(_hci_pkt->async){
			printf("\t\tHCI ASYNC:%s {");				

		}
		printf("\n\n\t\t}");
		printf("\n\n\t}\n\n");
}
void print_hci_packet(hci_pkt_t * _hci_pkt){

		if (!_hci_pkt){	
			return;
		}

		hci_pkt_cmd_t *_cmd_pkt = (hci_pkt_cmd_t*) _hci_pkt->cmd;
		hci_pkt_async_t *_async_pkt = (hci_pkt_async_t*) _hci_pkt->async;
		hci_pkt_event_t *_event_pkt = (hci_pkt_event_t*) _hci_pkt->event;

		if(_cmd_pkt != NULL){ //gotta check for cmd sonner
			hci_pkt_cmd_t *_cmd_pkt = &_hci_pkt->cmd;

			printf("\t\tHCI CMD: [%s] {",
				_hci_pkt->descr);				

			printf("\t\t* opcode -> '0x%.4x'\n",
				_cmd_pkt->opcode);

			printf("\t\t* opcode group   -> '0x%.2x'\n",
				OGF(_cmd_pkt->opcode));

			printf("\t\t* opcode command -> '0x%.2x'\n",
				OCF(_cmd_pkt->opcode));

			printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
				_cmd_pkt->param_len,
					_cmd_pkt->param_len);

		}else if(_event_pkt != NULL){
			printf("\t\tHCI EVENT:%s {");				
			printf("\t\t* event code -> '0x%.4x'\n",
				_event_pkt->event_code);
			printf("\t\t* param_len -> '0x%.2x' (%d) bytes \n",
				_event_pkt->param_len,
				_event_pkt->param_len);

		}else if(_hci_pkt->async){
			printf("\t\tHCI ASYNC:%s {");				

		}

}


void print_btpacket_record(unsigned int offset, btsnoop_packet_record_t * _bt_packet){

		time_t raw_time;
		char timestamp_buf[80]; 
		struct tm ts;
		unsigned int data_index = 0;
		//if (!_bt_packet){	
		//	return;
		//}

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
					printf("\t[0x%0.2x] ",_bt_packet->data[data_index]);
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
	hci_pkt_t *_hci_pkt = NULL;
	fseek(file,BT_FILE_HEADER_SZ,SEEK_SET); //reset pointer

	while (bytes_read != -1){
		//read the data field
		_bt_packet = (btsnoop_packet_record_t *) malloc(sizeof(btsnoop_packet_record_t));
		if (!_bt_packet){
			return NULL;
		}
			
		bytes_read = readseek_btpacket_record(file,_bt_packet);
		if (_bt_packet && _bt_packet->incl_length){
			index += 1;
			//unsigned int tell = ftell(file);		
			//print_btpacket_record(tell,_bt_packet);	 //this works, so now I need to build my linked list of bt packets
			//bt_packet_list[index++] = _bt_packet;					
			_bt_cur_list->record = _bt_packet;

			parse_hci(_hci_pkt,_bt_packet);
			print_hci_packet(_hci_cur_list->packet);

			//_hci_cur_list->packet = (hci_pkt_t *) malloc(sizeof(hci_pkt_t));
			//memcpy(_hci_cur_list->packet, _hci_pkt, sizeof(hci_pkt_t));

			_hci_cur_list->prev = _hci_prev_list; 
			_bt_cur_list->prev = _bt_prev_list;	

			btsnoop_packet_list_t *__bt_cur_prev = _bt_cur_list->prev;
			hci_packet_list_t *__hci_cur_prev = _hci_cur_list->prev;

			__bt_cur_prev->next = _bt_cur_list;
			__hci_cur_prev->next = _hci_cur_list;				
				
			_bt_prev_list = _bt_cur_list;
			_hci_prev_list = _hci_cur_list;

			_bt_cur_list->next = (btsnoop_packet_list_t *) malloc(sizeof(btsnoop_packet_list_t));
			_hci_prev_list->next = (hci_packet_list_t *) malloc(sizeof(hci_packet_list_t)); 

			_bt_cur_list = _bt_cur_list->next;
			_hci_cur_list = _hci_cur_list->next;

			//get_hci_packet(_bt_packet);	 //everything is in place now, we just need to map out the hci data
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
	//if (bytes_read != sizeof(bt_file_header->version)){
		printf("[x] didn't read full version value, bailing...\n");
		return NULL;
	}

	bytes_read = readseek_btsnoop_datalink_type(file,bt_file_header);
	if (bytes_read < 0){
	//if (bytes_read != sizeof(bt_file_header->datalink_type)){
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
	btsnoop_packet_list_t *_packet_list = get_bt_packets(argv[1]); //implement an btsnoop_hci_pkt_list_t so we can search through parsed packets
	if (_packet_list == NULL){
		printf("[x] problem reading packets\n");
	}
	hci_packet_list_t* _hci_packet_list = (hci_packet_list_t *) _packet_list->_hci_packet_list;
	unsigned int index = 0;
	printf("[*] printing records...\n");
	while (_packet_list != NULL){

			btsnoop_packet_record_t *_packet_record = (btsnoop_packet_record_t *)_packet_list->record;	
			hci_pkt_t * _hci_packet_ = (hci_pkt_t*) _hci_packet_list->packet;
			print_hci_packet(_hci_packet_);
			//print_btpacket_record_withhci(0,_packet_record,_hci_packet_);
			if (_hci_packet_ != NULL){
				printf("[*] found valid hci packet\n");
			}
			//if (_packet_record != NULL){
			//	print_btpacket_record_withhci(0,_packet_record,_hci_packet_); 
			//	//print_btpacket_record(0,_packet_record); 
			//}

			_packet_list = _packet_list->next;
			_hci_packet_list = _hci_packet_list->next;

			index++;
	}
	return 0;
}
