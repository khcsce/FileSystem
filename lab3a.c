#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
// 3a
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
// Header file
#include "ext2_fs.h"


// K
/*---------Globals--------*/
#define BLOCK 1024  // offset to superblock, boot size since boot block is 1024 bytes
#define REG 'f'
#define SYM 's'
#define DIR 'd'
#define UNKNOWN '?'
int fd; // the image
int blocks_count, block_size, blocks_per_group, inodes_count, inodes_per_group, inode_size;
char type;
// Header file structs (see: ext2_fs.h)
struct ext2_super_block superblock;
struct ext2_group_desc group;
struct ext2_inode inode;
struct ext2_dir_entry dir;


// K
/*----------------------Error functions exit(1) and exit(2)--------------*/
void print_error(const char* msg){
	fprintf(stderr, "%s , error number: %d, strerror: %s\n ",msg, errno, strerror(errno));
    exit(1);
}

void print_error2(const char* msg){
	fprintf(stderr, "%s , error number: %d, strerror: %s\n ",msg, errno, strerror(errno));
    exit(2);
}

/*--------------------------Helper functions-----------------------------*/
// K
ssize_t pread_with_check(int fd, void *buf, size_t size, off_t offset)
{
	ssize_t s = pread(fd,buf,size,offset);
	if(s < 0){
		print_error(("Error: reading error"));
	}
	return s;
}

// K
char* get_time(unsigned int time) {
  char* readable_date = malloc(sizeof(char) * 32);
  time_t rawtime = time;
  struct tm* t = gmtime(&rawtime);
  strftime(readable_date, 32, "%m/%d/%y %H:%M:%S", t);
  return readable_date;
}
/* There are six types of output lines that your program should produce,
each summarizing a different part of the file system. */

/*=========================Superblock===============================*/
// K
/* Parse and output data in superblock: recommended approach*/
void super_block_summary(){
	// TA Disccsion 1B Slides
	ssize_t superblock_size = sizeof(struct ext2_super_block);
	pread_with_check(fd,&superblock,superblock_size, BLOCK);

	blocks_count = superblock.s_blocks_count;
	block_size = EXT2_MIN_BLOCK_SIZE << superblock.s_log_block_size; /* calculate block size in bytes */
	blocks_per_group = superblock.s_blocks_per_group;

	inodes_count = superblock.s_inodes_count;
	inodes_per_group = superblock.s_inodes_per_group;

	inode_size = superblock.s_inode_size;
	// csv printing
	fprintf(stdout,"SUPERBLOCK,%d,%d,%d,%d,%d,%d,%d\n", blocks_count, inodes_count, block_size, inode_size,
		blocks_per_group, inodes_per_group, superblock.s_first_ino);

	// 8.  first non-reserved i-node (decimal)
}


/*========================Group====================================*/
/*
GROUP
group number (decimal, starting from zero)
total number of blocks in this group (decimal)
total number of i-nodes in this group (decimal)
number of free blocks (decimal)
number of free i-nodes (decimal)
block number of free block bitmap for this group (decimal)
block number of free i-node bitmap for this group (decimal)
block number of first block of i-nodes in this group (decimal)
*/

// ext2_group_desc marks the starting location of important blocks

// K
void group_summary(){

	ssize_t group_size = sizeof(struct ext2_group_desc);
	pread_with_check(fd,&group, group_size, BLOCK + sizeof(struct ext2_super_block));
	//  Based on slides 1B by TA, block group starts after the super block	
	/*Spec: But, in the images we give you, there will be only a single group.*/
	// So, group number = 0
	int group_num = 0;
	
	//int blocks_count = superblock.s_blocks_count;
	//int inodes_count = superblock.s_inodes_count;

	int free_blocks = group.bg_free_blocks_count;
	int free_inodes = group.bg_free_inodes_count;
	int block_bitmap = group.bg_block_bitmap;
	int inode_bitmap = group.bg_inode_bitmap;
	int first_inodes = group.bg_inode_table;

	fprintf(stdout,"GROUP,%d,%d,%d,%d,%d,%d,%d,%d\n", group_num, blocks_count, inodes_count, free_blocks,
		free_inodes, block_bitmap, inode_bitmap, first_inodes);
}


// NOTE TO SELF: we can put the free block and inode functions inside the group_summary function, but look into that later.

/*========================free block entries=====================*/
//Scan the free block bitmap for each group. For each free block, produce a new-line terminated line, with two comma-separated fields (with no white space).
// BFREE
// number of the free block (decimal)
// bit = 1 indicates if block is used (occupied by files or used by file system)
// 0 indicates the block is free (can be used by newly created/enlarged files)
// Note: block 0 is always used (boot block) -> block bitmap starts with block 1.

// K
void free_block_entries(){
// assume structure of figure shown in http://www.science.smith.edu/~nhowe/Teaching/csc262/oldlabs/ext2.html
	int byte;
	int bitmap_offset = group.bg_block_bitmap * BLOCK;
	char buf;
	for (byte = 0; byte < block_size; byte++) // iterate through the bit maps
	{
		pread_with_check(fd, &buf, 1, bitmap_offset + byte); // one byte at a time
		// Now we iterate through the individual bits of that specific byte we read from 
		for (int bit = 0; bit < 8; bit++) 
		{
			
			if((buf & (1 << bit)) == 0){
				fprintf(stdout, "BFREE,%d\n", (byte*8) + (bit + 1));
			}
		}
	}
}

/*========================free I-node entries=====================*/
// Scan the free I-node bitmap for each group. For each free I-node, produce a new-line terminated line, with two comma-separated fields (with no white space).
// IFREE
// number of the free I-node (decimal)
// Same logic applies as free_block_entires() function :)

// K
void free_inode_entries(){
	// assume structure of figure shown in http://www.science.smith.edu/~nhowe/Teaching/csc262/oldlabs/ext2.html
	int byte;
	int bitmap_offset = group.bg_inode_bitmap * BLOCK;
	char buf;
	for (byte = 0; byte < block_size; byte++) // iterate through the bit maps
	{
		pread_with_check(fd, &buf, 1, bitmap_offset + byte); // one byte at a time
		// Now we iterate through the individual bits of that specific byte we read from 
		for (int bit = 0; bit < 8; bit++) 
		{
			
			if((buf & (1 << bit)) == 0){
				fprintf(stdout, "IFREE,%d\n", (byte*8) + (bit + 1)); // see slides and link to understand
			}
		}
	}
}

// Careful on this: most difficult part
/*=============================Inode Table===========================*/  
// I-node Summary
// 		1) Directory
// 		2) Indirect block references

/*
I-node summary
Scan the I-nodes for each group. For each allocated (non-zero mode and non-zero link count) I-node, produce a new-line terminated line, with up to 27 comma-separated fields (with no white space). The first twelve fields are i-node attributes:
INODE
inode number (decimal)
file type ('f' for file, 'd' for directory, 's' for symbolic link, '?" for anything else)
mode (low order 12-bits, octal ... suggested format "%o")
owner (decimal)
group (decimal)
link count (decimal)
time of last I-node change (mm/dd/yy hh:mm:ss, GMT)
modification time (mm/dd/yy hh:mm:ss, GMT)
time of last access (mm/dd/yy hh:mm:ss, GMT)
file size (decimal)
number of (512 byte) blocks of disk space (decimal) taken up by this file
*/


/*======================1) Directory===========================*/  
/*
For each directory I-node, scan every data block. For each valid (non-zero I-node number) 
directory entry, produce a new-line terminated line, with seven comma-separated fields (no white space).

DIRENT
parent inode number (decimal) ... the I-node number of the directory that contains this entry
logical byte offset (decimal) of this entry within the directory
inode number of the referenced file (decimal)
entry length (decimal)
name length (decimal)
name (string, surrounded by single-quotes). Don't worry about escaping, we promise there will be no single-quotes or commas in any of the file names.
*/

void directory_summary(int i){
	// EXT2_NDIR_BLOCKS defined in headerfile , equals 12 which makes sense for direct cases
	for (int k = 0; k < EXT2_NDIR_BLOCKS; k++)
	{
		if (inode.i_block[k] != 0) // double check, for needless printing
		{
			for (int block_offset = 0; block_offset < BLOCK; block_offset += dir.rec_len )
			{
				pread_with_check(fd,&dir,sizeof(struct ext2_dir_entry),inode.i_block[k] * BLOCK + block_offset);
				if (dir.inode != 0){
					fprintf(stdout,"DIRENT,%d,%d,%d,%d,%d,\'%s\'\n",i+1,block_offset,dir.inode,dir.rec_len,dir.name_len,dir.name);
				}
			}
		}
	}
}



/*======================2) Indirect===========================*/  
/*
INDIRECT
	I-node number of the owning file (decimal)
	(decimal) level of indirection for the block being scanned ... 1 for single indirect, 2 for double indirect, 3 for triple
	logical block offset (decimal) represented by the referenced block. If the referenced block is a data block, this is the logical block offset of that block within the file. If the referenced block is a single- or double-indirect block, this is the same as the logical offset of the first data block to which it refers.
	block number of the (1, 2, 3) indirect block being scanned (decimal) . . . not the highest level block (in the recursive scan), but the lower level block that contains the block reference reported by this entry.
	block number of the referenced block (decimal)
*/

		/*
		i_block[0..11] point directly to the first 12 data blocks of the file.
		i_block[12] points to a single indirect block
		i_block[13] points to a double indirect block
		i_block[14] points to a triple indirect block
		– Direct Blocks = 12
		– Single Indirect Blocks = 256
		– Double Indirect Blocks = 256 * 256 = 65536
		– Triple Indirect Blocks = 256 * 256 * 256 = 16777216
		How does your offset change when you go through it?
		Direct blocks -> blocksize
		Indirect blocks? Multiply by blocksize per indirection level
		https://cgi.cse.unsw.edu.au/~cs3231/12s1/lectures/lect10x6.pdf
		*/
/*
http://www.dubeyko.com/development/FileSystems/ext2fs/ext2file.pdf

The first 12 entries in the i block[] array contain addresses to logical block numbers
0 through 11.
• The single-indirect entry at index 12 will eventually get you to blocks beginning with
block 12 and going up to block ( b4 + 11), with b being the block size; so in our
example, the single indirect block addresses blocks 12 - 267.
• The double-indirect entry at index 13 will address blocks from ( b4 + 12) through
(( b4)2 + b4 + 11); with a 1k block that’s blocks 268 through 65803
• The triple-indirect entry at index 14 can address blocks from (( b4)2 + b4 + 12) through
(( b4)3 + ( b4)2 + b4 + 12)–that’s a lot of blocks: from 65804 through (theoretically)
16843019.


*/

/*
From header file,
#define	EXT2_NDIR_BLOCKS		12
#define	EXT2_IND_BLOCK			EXT2_NDIR_BLOCKS
#define	EXT2_DIND_BLOCK			(EXT2_IND_BLOCK + 1)
#define	EXT2_TIND_BLOCK			(EXT2_DIND_BLOCK + 1)
*/
void indirect_helper(int i, int inode, int level, int start){
	// 	How does your offset change when you go through it?
	//	Direct blocks -> blocksize
	//	Indirect blocks? Multiply by blocksize per indirection level
	int base_offset = block_size * inode;
	int buf[block_size];
	pread_with_check(fd,buf,block_size, base_offset);
	for(int j = 0; j < block_size/4; j++){
		if(buf[j] != 0){
			int offset = start + j;
			if (level == 2){
				offset = start + (j * 256);
			}
			if (level == 3){
				offset = start + (j * 256 * 256);
			}
			fprintf(stdout, "INDIRECT,%d,%d,%d,%d,%d\n", i,level,offset, inode, buf[j]);
			if (level > 1) indirect_helper(i,buf[j], level - 1, offset);
		}
	}
}

void indirect_summary(int i){
	int bool_indirect = (type == REG || type == DIR);
	if (bool_indirect){
		indirect_helper(i + 1,inode.i_block[EXT2_IND_BLOCK], 1, 12);
		indirect_helper(i + 1,inode.i_block[EXT2_DIND_BLOCK], 2, 268);
		indirect_helper(i + 1,inode.i_block[EXT2_TIND_BLOCK], 3, 65804);
	}

}



/*============Inode Summary (indirect and directory_summary is called in here===============*/  

void inode_summary(){
	// struct ext2_inode inode;
	int flag = 1;
	int table_block = group.bg_inode_table;
	int inode_offset = block_size * table_block;
	for(int i = 0; i < inodes_count; i++){
		pread_with_check(fd, &inode, sizeof(struct ext2_inode), inode_offset+(i * sizeof(inode)));
		
		if(inode.i_mode == 0 || inode.i_links_count == 0) {// bypass this edge case !!!
			continue;
		}

		/*-------------------------Determine type of file with i_mode and stat----------*/
		
		/* If the file length is less than the size of the block pointers (60 bytes) the file will contain zero data blocks, and the name is stored in the space normally occupied by the block pointers.
		 If this is the case, the fifteen block pointers need not be printed.*/
		type = UNKNOWN;
		if(inode.i_mode == 0 || inode.i_links_count == 0){
			continue;
        }

		if(S_ISLNK(inode.i_mode)){
			type = SYM;
			// https://piazza.com/class/kirz3jfa5jv7l7?cid=633
			// Note, in the trival.csv, ignore the "1886221359" after the 0 for the Inode symbolic link one on line
			if (inode.i_size > 60){
				flag = 1;
			} else {
				flag = 0;
			}
        }
		else if(S_ISREG(inode.i_mode)){
			type = REG;
			flag = 1;
        }
		else if(S_ISDIR(inode.i_mode)){
			type = DIR;
			flag = 1;
        }

		/*--------------------Time-------------------------*/
		char* access = get_time(inode.i_atime);
		char* create = get_time(inode.i_ctime);
		char* modification = get_time(inode.i_mtime);


		/*-----------Print Inode Summary (basic)-----------*/
		int num_links = inode.i_links_count;
		int mode = inode.i_mode & 0xFFF;
		int owner = inode.i_uid;
		int group = inode.i_gid;
		int file_size = inode.i_size;
		int num_blocks = inode.i_blocks;

		fprintf(stdout,"INODE,%d,%c,%o,%d,%d,%d,%s,%s,%s,%d,%d",i+1,type,mode,owner,group,num_links,create,modification,access,
			file_size,num_blocks);

		// FREE time char strings
		free(access);
		free(create);
		free(modification);

		/* If the file length is less than the size of the block pointers (60 bytes) the file will contain zero data blocks, and the name is stored in the space normally occupied by the block pointers.
		 If this is the case, the fifteen block pointers need not be printed.*/

		/*
		 For each allocated (non-zero mode and non-zero link count) I-node, produce a new-line terminated line, with up to 27 comma-separated fields (with no white space).
		  The first twelve fields are i-node attributes:
		  15 + 12 = 27
		*/

		if (flag == 1){
			for (int j = 0; j < 15; j++){
				fprintf(stdout,",%d",inode.i_block[j]);
			}
		}
		fprintf(stdout,"\n"); // new line for next csv line to be printed correctly

		/*-----------------------Directory-------------------------*/
		if(type == DIR){
			directory_summary(i);
		}

		/*----------------------Indirect---------------------------*/
		indirect_summary(i);
	}
}


/*
void printer(){
	//super_block_summary();
	// group_summary();
	// free_block_entries();
	// free_inodes_entries();
	// inode_summary();

	// ADD later
}*/

// K
int main(int argc, char** argv){
	if(argc !=2){
		print_error("Error: incorrect arguments");
	}
	fd = open(argv[1],O_RDONLY);
	if (fd < 0){
		print_error("Error: opening image file");
	}
	super_block_summary();
	group_summary();
	free_block_entries();
	free_inode_entries();
	inode_summary();
	exit(0);
}

