#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 512
#define NAME "archive.tar"
#define SUCCESS "success_"

struct tar_t
{                              /* byte offset */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */
    char devminor[8];             /* 337 */
    char prefix[155];             /* 345 */
    char padding[12];             /* 500 */
};

// Path to the executable
char path[26];
// nth file tested
int ntry;

/** 
 * Test if the archive crashes the extractor and saves it if it crashes
 * @param name the name of archive to test
 * @return -1 if the extractor cannot be launched
 *          0 if it doesn't crash
 *          1 if it crashes
*/
int testarchive(char name[]) {
    char cmd[51];
    strncpy(cmd,path,26);
    strncat(cmd,"  ",1);
    strncat(cmd,name,24);
    char buf[33];
    FILE *fp;
    int res = 0;
    if ((fp = popen(cmd,"r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }
    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
    }
    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
    } else {
        printf("Crash message\n");
        res = 1;
    }
    if (pclose(fp) == -1) {
        printf("Command not found\n");
        res = -1;
    }
    // Saves the archive
    if (res == 1) {
        char new[33];
        sprintf(new,"%s%d.tar",SUCCESS,ntry);
        rename(name,new);
    }
    return res;
}

/**
 * Creates an archive with the right format containing n files
 * @param name the name of the archive
 * @param n the number of files in the archive
 * @param headers the headers of the files in the archive
 * @param contents the content of the files in the archive
 * @return -1 if the creation fails or 0 if it succeed
 */
int createarchive(char name[], int n, struct tar_t headers[], char contents[][BLOCK_SIZE]) {
    FILE *fd;

    if ((fd = fopen(name,"w")) == NULL) {
        printf("Error creating archive\n");
        return -1;
    }
    // Loop writing successive headers and files
    for (int i = 0; i < n; i++) {
        fwrite(&(headers[i]),sizeof(char),BLOCK_SIZE,fd);
        fwrite(contents[i],sizeof(char),BLOCK_SIZE,fd);
    }
    // End of archive blocks
    char empty_block[BLOCK_SIZE] = {0};
    fwrite(empty_block,sizeof(char),BLOCK_SIZE,fd);
    fwrite(empty_block,sizeof(char),BLOCK_SIZE,fd);

    if (fclose(fd) != 0) {
        printf("Error closing file\n");
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        return -1;
    }
    // Getting path to the extractor
    strncpy(path,argv[1],25);
    path[26] = '\0';
    
    // Initialization
    ntry = 1;
    int running = 1;
    int cases = 1;  // test case

    printf("Begin fuzzing");
    while (running) {
        struct tar_t head;
        char content[1][BLOCK_SIZE];
        switch (cases) {
            // Testing non-ascii character in name
            case 1:
                memset(content[1],0,BLOCK_SIZE);
                memset(&head,0,BLOCK_SIZE);
                for (char c = 128; c < 138; c++) {
                    printf(head.name,"file%c",c);
                    createarchive(NAME,1,&head,content);
                }
                cases++;
                break;
            default:
            printf("Stop fuzzing");    
            running = 0;
        }
    }
    
    return 0;
}