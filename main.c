/*
 * Copyright (C) 2017 Harry Jiang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <stdbool.h>

#define GPT_RESERVED 420
#define LBA_SIZE 512
#define GPT_SIGNATURE "EFI PART"

struct mbr_partition {
    uint8_t status;
    uint8_t first_sector[3];
    uint8_t partition_type;
    uint8_t last_sector[3];
    uint32_t first_lba;
    uint32_t length_lba;
} __attribute__((packed));

struct mbr {
    uint8_t code[446];
    struct mbr_partition partitions[4];
    uint16_t mbr_signature;
} __attribute__((packed));

struct gpt_partition {
    uint8_t partition_type[16];
    uint8_t unique_guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attributes;
    uint8_t partition_name[72];
} __attribute__((packed));

struct gpt_hdr {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];
    uint64_t partition_entries_lba;
    uint32_t num_parts;
    uint32_t sizeof_partition_entries;
    uint32_t partition_entries_crc;
    unsigned char reserved2[GPT_RESERVED];
} __attribute__((packed)); // struct GPTHeader

uint32_t crc_tab[256];

uint32_t chksum_crc32(uint8_t *block, uint32_t length)
{
    unsigned long crc;
    unsigned long i;

    crc = 0xFFFFFFFF;

    for (i = 0; i < length; i++) {
        crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
    }

    return (crc ^ 0xFFFFFFFF);
}

void chksum_crc32gentab()
{
    unsigned long crc, poly;
    int i, j;

    poly = 0xEDB88320L;
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 8; j > 0; j--) {
            if (crc & 1) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        crc_tab[i] = crc;
   }
}

int open_file(FILE **file, char *path)
{
    *file = fopen(path, "r+b");

    if (*file == NULL) {
        printf("Open file error: %s\n", strerror(errno));
        return errno;
    }

    return 0;
}

uint64_t get_partition_sectors(struct gpt_hdr *hdr)
{
    return (hdr->num_parts * hdr->sizeof_partition_entries + LBA_SIZE - 1) / LBA_SIZE;
}

int read_gpt_hdr(FILE *file, struct gpt_hdr *hdr)
{
    int ret = 0;

    ret = fseek(file, sizeof(struct mbr), SEEK_SET);
    if (ret) {
        printf("Set seek error: %s\n",strerror(errno));
        return -1;
    }

    ret = fread(hdr, sizeof(struct gpt_hdr), 1, file);
    if (ret != 1) {
        printf("Read gpt error: %d\n", ret);
        return -1;
    }

    return 0;
}

int write_gpt_hdr(FILE *file, struct gpt_hdr *hdr)
{
    int ret = 0;
    uint32_t crc;

    ret = fseek(file, sizeof(struct mbr), SEEK_SET);
    if (ret) {
        printf("Set seek error: %s\n",strerror(errno));
        return -1;
    }

    hdr->header_crc = 0;
    crc = chksum_crc32((uint8_t *)hdr, hdr->header_size);
    hdr->header_crc = crc;

    ret = fwrite(hdr, sizeof(struct gpt_hdr), 1, file);
    if (ret != 1) {
        printf("write gpt error: %d\n", ret);
        return -1;
    }

    ret = fseek(file, hdr->backup_lba * LBA_SIZE, SEEK_SET);
    if (ret) {
        printf("Set seek error: %s\n",strerror(errno));
        return -1;
    }

    hdr->current_lba = hdr->backup_lba;
    hdr->backup_lba = 1;
    hdr->partition_entries_lba = hdr->current_lba - get_partition_sectors(hdr);

    hdr->header_crc = 0;
    crc = chksum_crc32((uint8_t *)hdr, hdr->header_size);
    hdr->header_crc = crc;

    ret = fwrite(hdr, sizeof(struct gpt_hdr), 1, file);
    if (ret != 1) {
        printf("write backup gpt error: %d\n", ret);
        return -1;
    }

    return 0;
}

bool verify_gpt_hdr(struct gpt_hdr *hdr)
{
    uint32_t crc;
    uint32_t backup_crc = hdr->header_crc;
    bool ret = true;

    if (memcmp(&hdr->signature, GPT_SIGNATURE, sizeof(uint64_t))) {
        printf("This is not GUID partition table\n");
        return false;
    }

    chksum_crc32gentab();

    hdr->header_crc = 0;

    crc = chksum_crc32((uint8_t *)hdr, hdr->header_size);
    if (crc != backup_crc) {
        printf("Check crc error\n");
        ret = false;
    }

    hdr->header_crc = backup_crc;

    return ret;
}

int read_partition_table(FILE *file, struct gpt_hdr *hdr, struct gpt_partition *partitions)
{
    int ret;

    ret = fseek(file, hdr->partition_entries_lba * LBA_SIZE, SEEK_SET);
    if (ret) {
        printf("Set seek error: %s\n",strerror(errno));
        return -1;
    }

    ret = fread(partitions, hdr->sizeof_partition_entries, hdr->num_parts, file);
    if (ret != hdr->num_parts) {
        printf("Read partition error: %d\n", ret);
        return -1;
    }

    return 0;
}

int write_partition_table(FILE *file, struct gpt_hdr *hdr, struct gpt_partition *partitions)
{
    int ret;

    ret = fseek(file, hdr->partition_entries_lba * LBA_SIZE, SEEK_SET);
    if (ret) {
        printf("Set seek error: %s\n",strerror(errno));
        return -1;
    }

    ret = fwrite(partitions, hdr->sizeof_partition_entries, hdr->num_parts, file);
    if (ret != hdr->num_parts) {
        printf("Write partition error: %d\n", ret);
        return -1;
    }

    return 0;
}

int remove_partition_table(FILE *file, struct gpt_hdr *hdr)
{
    int ret;
    int i;
    struct gpt_partition empty_partition;

    memset(&empty_partition, 0x00, sizeof(struct gpt_partition));

    ret = fseek(file, hdr->partition_entries_lba * LBA_SIZE, SEEK_SET);
    if (ret) {
        printf("Set seek error: %s\n",strerror(errno));
        return -1;
    }

    for (i = 0; i < hdr->num_parts; i++) {
        ret = fwrite(&empty_partition, sizeof(struct gpt_partition), 1, file);
        if (ret != 1) {
            printf("remove partition error: %d %d i:%d, %d\n", ret, hdr->sizeof_partition_entries, i, ferror(file));
            return -1;
        }
    }


    return 0;
}

uint64_t find_first_partition(struct gpt_partition *partitions, int length)
{
    int i;
    uint64_t min_lba = -1;

    for (i = 0; i < length; i++) {
        if (partitions[i].first_lba > 0) {
            if (min_lba == -1) {
                min_lba = partitions[i].first_lba;
            } else if (partitions[i].first_lba < min_lba) {
                min_lba = partitions[i].first_lba;
            }

        }
    }

    return min_lba;
}

int main(int argc, char *argv[]) {
    FILE *gpt_file;
    struct gpt_hdr *hdr;
    struct gpt_partition *partitions;
    uint64_t first_lba;
    uint64_t paritions_sectors;
    char *dev = NULL;
    int err = 0;
    int partition_start_sector = -1;
    int opt;
    int ret;

    if (argc < 5) {
        printf("Usage: %s\n", argv[0]);
        printf("  -d <device> (storage with GUID partition table)\n");
        printf("  -s <sector> (partition table move to)\n");
        printf("\n");
        printf("Example %s -s /dev/sdd -s 2\n", argv[0]);
        return 0;
    }


    while ((opt = getopt(argc, argv, "d:s:")) != -1) {
        switch (opt) {
        case 'd':
            dev = optarg;
            break;
        case 's':
            partition_start_sector = strtol(optarg, NULL, 0);
            break;
        }
    }

    if (!dev) {
        printf("No file to open\n");
        return -1;
    }

    if (partition_start_sector <  2) {
        printf("Partition table start sector should large than 1\n");
        return -1;
    }

    ret = open_file(&gpt_file, dev);
    if (ret) {
        err = -1;
        goto out;
    }

    hdr = malloc(sizeof(struct gpt_hdr));
    if (hdr == NULL) {
        printf("%s\n", strerror(ENOMEM));
        err = -ENOMEM;
        goto file;
    }

    ret = read_gpt_hdr(gpt_file, hdr);
    if (ret) {
        err = -1;
        goto mem;
    }

    ret = !verify_gpt_hdr(hdr);
    if (ret) {
        printf("Bad Guid partition table\n");
        goto mem;
    }

    partitions = malloc(hdr->num_parts * hdr->sizeof_partition_entries);
    if (partitions == NULL) {
        printf("%s\n", strerror(ENOMEM));
        err = -ENOMEM;
        goto mem;
    }

    ret = read_partition_table(gpt_file, hdr, partitions);
    if (ret) {
        printf("Read partition error\n");
        err = -1;
        goto mem2;
    }

    paritions_sectors = get_partition_sectors(hdr);

    first_lba = find_first_partition(partitions, hdr->num_parts);
    if (first_lba < 0) {
        printf("No partition found\n");
        first_lba = hdr->last_usable_lba - paritions_sectors;
    }


    if ((partition_start_sector + paritions_sectors) > first_lba) {
        printf("Can not move partition table\n");
        err = -1;
        goto mem2;
    }

    ret = remove_partition_table(gpt_file, hdr);
    if (ret) {
        printf("Remove partition table error\n");
        err = -1;
        goto mem2;
    }

    hdr->partition_entries_lba = partition_start_sector;
    hdr->first_usable_lba = partition_start_sector + paritions_sectors;

    ret = write_partition_table(gpt_file, hdr, partitions);
    if (ret) {
        printf("Write partition table error\n");
        err = -1;
        goto mem2;
    }

    ret = write_gpt_hdr(gpt_file, hdr);
    if (ret) {
        printf("Write GPT header error\n");
        err = -1;
        goto mem2;
    }
    
mem2:
    free(partitions);
mem:
    free(hdr);
file:
    fclose(gpt_file);
out:
    return err;
}
