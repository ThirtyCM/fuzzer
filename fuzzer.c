#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BLOCK_SIZE 512
#define MAGIC "ustar"
#define VERSION "00"
#define NAME "test.tar"
#define SUCCESS "success_"

struct tar_t {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};

// Path to the executable
char path[26];
int ntry;

unsigned int calculate_checksum(struct tar_t *header) {
    memset(header->chksum, ' ', 8);
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) header;
    for (int i = 0; i < 512; i++) {
        check += raw[i];
    }
    snprintf(header->chksum, sizeof(header->chksum), "%06o0", check);
    header->chksum[6] = '\0';
    header->chksum[7] = ' ';
    return check;
}

int testarchive(char name[]) {
    char cmd[128];
    snprintf(cmd, 128, "%s %s", path, name);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        printf("Error opening pipe!\n");
        return -1;
    }

    char buf[64];
    int res = 0;
    if (fgets(buf, 64, fp) && strstr(buf, "*** The program has crashed ***")) {
        printf("Crash detected! Saving %s\n", name);
        res = 1;
    }
    pclose(fp);

    if (res == 1) {
        char new_name[33];
        sprintf(new_name, "%s%d.tar", SUCCESS, ntry);
        rename(name, new_name);
    } else {
        unlink(name); // it eliminates the files that not crash de program, because lot of them are generated
    }

    ntry++;
    return res;
}

int createarchive(char name[], int n, struct tar_t headers[], char contents[][BLOCK_SIZE]) {
    FILE *fd = fopen(name, "w");
    if (!fd) {
        printf("Error creating archive\n");
        return -1;
    }

    for (int i = 0; i < n; i++) {
        fwrite(&(headers[i]), sizeof(char), BLOCK_SIZE, fd);
        fwrite(contents[i], sizeof(char), BLOCK_SIZE, fd);
    }

    char empty_block[BLOCK_SIZE] = {0};
    fwrite(empty_block, sizeof(char), BLOCK_SIZE, fd);
    fwrite(empty_block, sizeof(char), BLOCK_SIZE, fd);

    fclose(fd);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        return -1;
    }

    strncpy(path, argv[1], 25);
    path[26] = '\0';

    ntry = 1;
    printf("Begin fuzzing\n");

    struct tar_t head;
    char content[1][BLOCK_SIZE];
    memset(content[0], 'X', BLOCK_SIZE - 1);
    content[0][BLOCK_SIZE - 1] = '\0';
    memset(&head, 0, BLOCK_SIZE);

    int test_cases = 6;

    //different cases to try crash the extractor
    for (int case_id = 1; case_id <= test_cases; case_id++) {
        switch (case_id) {
            case 1:
                printf("Testing typeflag with unexpected value\n");
                snprintf(head.name, 100, "file.txt");
                snprintf(head.mode, 8, "0000777"); // maximum permissions
                snprintf(head.size, 12, "%011o", (unsigned int) 1024);
                head.typeflag = 'Z'; // unexpected value
                snprintf(head.magic, 6, MAGIC);
                strcpy(head.version, VERSION);
                snprintf(head.uid, 8, "0000000"); // UID valid in octal

                snprintf(head.gid, 8, "0000000"); // GID valid in octal
                calculate_checksum(&head);
                createarchive(NAME, 1, &head, content);
                testarchive(NAME);
                break;

            case 2:
                printf("Testing large but valid size\n");
                snprintf(head.size, 12, "%011o", (unsigned int) 07777777777); // big size bt in octal
                calculate_checksum(&head);
                createarchive(NAME, 1, &head, content);
                testarchive(NAME);
                break;

            case 3:
                printf("Testing non-standard padding in TAR structure\n");
                snprintf(head.uid, 8, "0001750"); // UID valid
                snprintf(head.gid, 8, "0001750"); // GID valid
                memset(head.padding, 'X', 12); // for the unexpected values ​​in padding
                calculate_checksum(&head);
                createarchive(NAME, 1, &head, content);
                testarchive(NAME);
                break;

            case 4:
                printf("Testing corrupted linkname\n");
                snprintf(head.linkname, 100, "corrupt_link"); //// entering unexpected characters
                calculate_checksum(&head);
                createarchive(NAME, 1, &head, content);
                testarchive(NAME);
                break;

            case 5:
                printf("Testing unexpected extra data after EOF\n");
                createarchive(NAME, 1, &head, content);
                FILE *fd = fopen(NAME, "a");
                if (fd) {
                    fwrite("EXTRADATA", sizeof(char), 9, fd); // Add data after EOF
                    fclose(fd);
                }
                testarchive(NAME);
                break;

            case 6:
                printf("Testing archive with truncated header\n");
                FILE *fd2 = fopen(NAME, "w");
                if (fd2) {
                    fwrite(&head, sizeof(char), BLOCK_SIZE / 2, fd2); //
                    fclose(fd2);
                }
                testarchive(NAME);
                break;

            case 7:
                printf("Testing non-ASCII characters in name field\n");
                memset(content[0], 'X', BLOCK_SIZE - 1);
                content[0][BLOCK_SIZE - 1] = '\0';
                for (int c = 128; c < 256; c++) { 
                    snprintf(head.name, 100, "file%c.txt", (char) c);
                    snprintf(head.mode, 8, "0644");
                    snprintf(head.uid, 8, "0001750");
                    snprintf(head.gid, 8, "0001750");
                    snprintf(head.size, 12, "%011o", (unsigned int) 1024);
                    head.typeflag = '0';
                    snprintf(head.magic, 6, MAGIC);
                    strcpy(head.version, VERSION);
                    calculate_checksum(&head);
                    createarchive(NAME, 1, &head, content);
                    testarchive(NAME);
                }
                break;


            default:
                printf("Stopping fuzzing\n");
                return 0;
        }
    }

    return 0;
}

