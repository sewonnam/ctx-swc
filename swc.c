#include <stdio.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "swc.h"
#include "swc.skel.h"

static volatile bool exiting;

void sig_handler(int sig)
{
    exiting = true;
}

int print_data(struct bpf_map *datas)
{
    int err, lookup_key, next_key;
    int fd;
    struct data data;

    fd = bpf_map__fd(datas);
    while(!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &data);
        if (err < 0) {
            fprintf(stderr, "failed to lookup data: %d\n", err);
            return -1;
        }

        printf("%-16s %d\n", data.comm, data.count);
        lookup_key = next_key;
    }
    return 0;
}

int main()
{
    struct swc_bpf *obj;
    int err;

    obj = swc_bpf__open();
    if (!obj) {
        fprintf(stderr, "Failed to open object\n");
        return 1;
    }

    err = swc_bpf__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load object\n");
        goto cleanup;
    }

    err = swc_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "Failed to attach programs\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    printf("Tracing process context-switching count... Ctrl-C to end.\n");

    while (1) {
        if (exiting)
            break;
    }

    printf("\n");
    printf("%-16s %s\n", "COMM", "COUNT");

    err = print_data(obj->maps.datas);
    if (err)
        goto cleanup;

cleanup:
    swc_bpf__destroy(obj);
    return err != 0;
}
