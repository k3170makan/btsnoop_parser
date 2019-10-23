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


#define DATA_LINK_TYPE_RESERVED 1000
#define DATA_LINK_TYPE_UNENCAP 1001
#define DATA_LINK_TYPE_HCI_UART 1002
#define DATA_LINK_TYPE_HCI_BSCP 1003
#define DATA_LINK_TYPE_HCI_SERIAL 1004
#define DATA_LINK_TYPE_UNASSIGNED 1005

#define HCI_CMD_PKT 0x1
#define HCI_ASYNC_DATA_PKT 0x2
#define HCI_SYNC_DATA_PKT 0x3
#define HCI_EVENT_PKT 0x4
#define HCI_EXT_CMD_PKT 0x9 #probably vendor commands?

typedef struct btsnoop_hci_cmd_packet_t{
	unsigned char opcode; 
	unsigned char param_length;
	unsigned char params[0];  
	
} hci_cmd_packet_t;

typedef struct btsnoop_hci_async_data_packet_t{
	unsigned char handle; 
	unsigned char data_length;
	unsigned char data[0];  

} hci_async_data_packet_t;

typedef struct btsnoop_hci_event_packet_t{
	unsigned char event_code; 
	unsigned char param_length;
	unsigned char params[0];  

} hci_event_packet_t;


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


typedef struct btsnoop_packet{
	btsnoop_packet_record_t *record;
	btsnoop_packet_record_t *next;
	
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

//some constants for fseek and fread

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




btsnoop_header_t* open_hci_log(const char*);
FILE* show_header(FILE *);
btsnoop_header_t* init_bt_header(FILE *);
static void print_bt_header(btsnoop_header_t *);
static void print_btpacket_record(unsigned int, btsnoop_packet_record_t *);

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
void print_btpacket_record(unsigned int offset, btsnoop_packet_record_t * _bt_packet){

		time_t raw_time;
		char timestamp_buf[80]; 
		struct tm ts;
		unsigned int data_index = 0;
		if (!_bt_packet){	
			return;
		}

		printf("(%d)[0x%.2x] btsnoop_packet_record_t {\n",offset,offset);
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

btsnoop_packet_record_t* get_bt_packets(const char *filename){

	
	FILE *file = fopen(filename,"r");

	if (!file){
		printf("[x] problem opening file\n");
		return NULL;
	}
	btsnoop_packet_record_t **bt_packet_list;
	btsnoop_packet_record_t *_bt_packet = (btsnoop_packet_record_t *) malloc(sizeof(btsnoop_packet_record_t));
	ssize_t bytes_read; 
	unsigned int index;
	char *cur_data;
	unsigned int data_index;
	fseek(file,BT_FILE_HEADER_SZ,SEEK_SET); //reset pointer
	//bt_packet_list =	(btsnoop_packet_record_t **) malloc(sizeof(btsnoop_packet_record_t *)*MAX_PACKET_LIST_SZ);

	while (bytes_read != -1){
		//read the data field
		_bt_packet = (btsnoop_packet_record_t *) malloc(sizeof(btsnoop_packet_record_t));
		bytes_read = readseek_btpacket_record(file,_bt_packet);
		if (_bt_packet && _bt_packet->incl_length){
			//bt_packet_list[index++] = _bt_packet;					
			unsigned int tell = ftell(file);		
			print_btpacket_record(tell,_bt_packet);	 //this works, so now I need to build my linked list of bt packets
			//get_hci_packet(_bt_packet);	 //everything is in place now, we just need to map out the hci data
		}
	}
	
	return bt_packet_list;
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
	get_bt_packets(argv[1]);

	return 0;
}

