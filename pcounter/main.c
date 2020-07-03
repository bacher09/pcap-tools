#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <poll.h>
#include <popt.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <math.h>

#define MAX_PCAP_EXPR_LEN 512
#define NSEC_IN_SEC 1000000000UL

enum capture_type {
    CAPTURE_LIVE = 15,
    CAPTURE_OFFLINE = 16,
};

enum bytes_units {
    PACKET_SIZE_BYTES = 1,
    PACKET_SIZE_KIBIBYTES = 2,
    PACKET_SIZE_MEBIBYTES = 3,
    PACKET_SIZE_GIBIBYTES = 4,
};

struct app_state {
    char* interface;
    char* pcap_file;
    float interval;
    enum bytes_units packet_size_units;
    char filter_buf[MAX_PCAP_EXPR_LEN];
};

struct size_units_info {
    const char* name;
    float divider;
};

struct live_capture_state {
    struct timespec start_time;
    unsigned long long interval_count;
    unsigned long long interval_bytes;
    unsigned long long summary_count;
    unsigned long long summary_bytes;
};

static bool sigint_received = false;

static inline bool timespec_after_oreq(
    const struct timespec *tm1,
    const struct timespec *tm2
) {
    if (tm1->tv_sec == tm2->tv_sec) {
        return tm1->tv_nsec <= tm2->tv_nsec;
    } else {
        return tm1->tv_sec <= tm2->tv_sec;
    }
}

static inline float timediff_f(const struct timespec *tm1, const struct timespec *tm2) {
    struct timespec temp;
    temp.tv_sec = tm1->tv_sec - tm2->tv_sec;
    temp.tv_nsec = tm1->tv_nsec - tm2->tv_nsec;
    if (temp.tv_nsec < 0) {
        temp.tv_nsec += NSEC_IN_SEC;
        temp.tv_sec--;
    }
    return (float)temp.tv_sec + ((float)temp.tv_nsec / 1e9f);
}

static void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct live_capture_state *capture_state = (struct live_capture_state*)args;
    capture_state->interval_count++;
    capture_state->interval_bytes += header->len;
}

static void sigint_handler(int sig) {
    sigint_received = true;
}

static void snfmt_bytes(unsigned long long bytes, enum bytes_units unit, char *out, size_t size) {
    switch(unit) {
        case PACKET_SIZE_BYTES:
            snprintf(out, size, "%7llu bytes", bytes);
            break;
        case PACKET_SIZE_KIBIBYTES:
            snprintf(out, size, "%7.2f Kib", (float)bytes / 1024);
            break;
        case PACKET_SIZE_MEBIBYTES:
            snprintf(out, size, "%7.2f Mib", (float)bytes / (1024 * 1024));
            break;
        case PACKET_SIZE_GIBIBYTES:
            snprintf(out, size, "%7.2f Gib", (float)bytes / (1024 * 1024 * 1024));
            break;
    }
}

static noreturn void handle_live(struct app_state* state) {
    int ret;
    int pcap_fd;
    bpf_u_int32 net, mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    fd_set readfds;
    struct timespec interval, next_output, waittime, cur_time;
    struct live_capture_state capture_state;
    struct sigaction sa;
    pcap_t *handle;
    char bytes_str[64];

    memset(&capture_state, 0, sizeof(capture_state));
    if (pcap_lookupnet(state->interface, &net, &mask, errbuf) == PCAP_ERROR) {
        perror("Failed to open interface");
        exit(2);
    }
    // TODO: Maybe change packet buffer timeout ?
    handle = pcap_open_live(state->interface, 0, 0, 200 , errbuf);
    if (handle == NULL) {
        perror("Failed to create libpcap handle");
        exit(2);
    }
    pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd == PCAP_ERROR) {
        pcap_perror(handle, "Failed to get capture fd");
        exit(2);
    }
    if (pcap_setnonblock(handle, 1, "Failed to switch to non-blocking mode") == PCAP_ERROR) {
        pcap_perror(handle, "Pcap error: ");
        exit(2);
    }
    if (pcap_compile(handle, &bpf_filter, state->filter_buf, 1, net) == PCAP_ERROR) {
        pcap_perror(handle, "Failed to compile expression");
        exit(2);
    }
    if (pcap_setfilter(handle, &bpf_filter) == PCAP_ERROR) {
        pcap_perror(handle, "Failed to attach filter");
        exit(2);
    }
    interval.tv_sec = (int)truncf(state->interval);
    interval.tv_nsec = (int)roundf((state->interval - truncf(state->interval)) * 1e9);
    clock_gettime(CLOCK_MONOTONIC, &capture_state.start_time);
    next_output.tv_sec = capture_state.start_time.tv_sec + interval.tv_sec;
    next_output.tv_nsec = capture_state.start_time.tv_nsec + interval.tv_nsec;
    memcpy(&waittime, &interval, sizeof(waittime));
    FD_ZERO(&readfds);
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to register SIGINT handler");
        exit(2);
    }
    for (;;) {
        FD_SET(pcap_fd, &readfds);
        ret = pselect(pcap_fd + 1, &readfds, NULL, NULL, &waittime, NULL);
        if (ret < 0 && errno != EINTR) {
            perror("Error calling select");
            exit(3);
        }
        clock_gettime(CLOCK_MONOTONIC, &cur_time);
        if (timespec_after_oreq(&next_output, &cur_time)) {
            /* Output counters */
            float td = timediff_f(&cur_time, &capture_state.start_time);
            snfmt_bytes(capture_state.interval_bytes, state->packet_size_units, bytes_str, sizeof(bytes_str));
            printf("Time: %5.2f\tPackets: %5llu\tData: %s\n", td, capture_state.interval_count,
                   bytes_str);
            /* Reset counters and update summary */
            capture_state.summary_count += capture_state.interval_count;
            capture_state.summary_bytes += capture_state.interval_bytes;
            capture_state.interval_count = 0;
            capture_state.interval_bytes = 0;

            /* Calculate next output time */
            while (!timespec_after_oreq(&cur_time, &next_output)) {
                next_output.tv_sec += interval.tv_sec;
                next_output.tv_nsec += interval.tv_nsec;
                if (next_output.tv_nsec >= NSEC_IN_SEC) {
                    next_output.tv_nsec -= NSEC_IN_SEC;
                    next_output.tv_sec++;
                }
            }

        }
        if (ret > 0 && FD_ISSET(pcap_fd, &readfds)) {
            pcap_dispatch(handle, 100, process_packet, (u_char*)&capture_state);
        }
        if (sigint_received) {
            /* Update summary */
            capture_state.summary_count += capture_state.interval_count;
            capture_state.summary_bytes += capture_state.interval_bytes;
            goto done;
        }
        /* Calculate waittime */
        waittime.tv_sec = next_output.tv_sec - cur_time.tv_sec;
        waittime.tv_nsec = next_output.tv_nsec - cur_time.tv_nsec;
        if (waittime.tv_nsec < 0) {
            waittime.tv_nsec += NSEC_IN_SEC;
            waittime.tv_sec--;
        }
    }
done:
    clock_gettime(CLOCK_MONOTONIC, &cur_time);
    snfmt_bytes(capture_state.summary_bytes, state->packet_size_units, bytes_str, sizeof(bytes_str));
    float capture_time = timediff_f(&cur_time, &capture_state.start_time);
    float average_pps = (float)capture_state.summary_count / capture_time;
    float average_data = (float)capture_state.summary_bytes / capture_time;
    printf("\n---  Summary  ---\nTotal time: %5.2f seconds, Packets: %llu, Data: %s\n",
            capture_time, capture_state.summary_count, bytes_str);
    printf("Avg PPS: %8.2f, Avg Data Rate:", average_pps);
    switch (state->packet_size_units) {
        case PACKET_SIZE_BYTES:
            printf("%8.2f byte/s %8.2f bit/s\n", average_data, average_data * 8);
            break;
        case PACKET_SIZE_KIBIBYTES:
            average_data /= 1024;
            printf("%8.2f Kib/s %8.2f Kbit/s\n", average_data, average_data * 8);
            break;
        case PACKET_SIZE_MEBIBYTES:
            average_data /= 1024 * 1024;
            printf("%8.2f Mib/s %8.2f Mbit/s\n", average_data, average_data * 8);
            break;
        case PACKET_SIZE_GIBIBYTES:
            average_data /= 1024 * 1024 * 1024;
            printf("%8.2f Gib/s %8.2f Gbit/s\n", average_data, average_data * 8);
            break;
    }
    exit(0);
}

static noreturn void handle_offline(struct app_state* state) {
    fputs("Sorry this isn't implemented yet\n", stderr);
    exit(0);
}

int main(int argc, const char *argv[]) {
    int ret;
    struct app_state state;
    const char **filters;
    int filter_size;
    poptContext optCon;
    enum capture_type op_type = 0;
    struct poptOption optionsTable[] = {
        {
            "interface", 'i', POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT,
            &state.interface, CAPTURE_LIVE, "listening interface", "DEV"
        },
        {
            "file", 'r', POPT_ARG_STRING,
            &state.pcap_file, CAPTURE_OFFLINE, "input pcap file", "PCAP_FILE"
        },
        {
            "interval", 't', POPT_ARG_FLOAT | POPT_ARGFLAG_SHOW_DEFAULT,
            &state.interval, 0, "update interval (seconds)", "INTERVAL"
        },
        {
            "bytes", 'b', POPT_ARG_NONE, NULL, PACKET_SIZE_BYTES,
            "Display packet size in bytes", NULL
        },
        {
            "kibi", 'k', POPT_ARG_NONE, NULL, PACKET_SIZE_KIBIBYTES,
            "Display packet size in kibiytes", NULL
        },
        {
            "mebi", 'm', POPT_ARG_NONE, NULL, PACKET_SIZE_MEBIBYTES,
            "Display packet size in mebibytes", NULL
        },
        {
            "gibi", 'g', POPT_ARG_NONE, NULL, PACKET_SIZE_GIBIBYTES,
            "Display packet size in gibibytes", NULL
        },
        POPT_AUTOHELP
        { NULL, 0, 0, NULL, 0 }
    };
    bool bytes_unit_selected = false;

    memset(&state, 0, sizeof(state));
    state.interface = "any";
    state.interval = 1.0f;
    state.packet_size_units = PACKET_SIZE_KIBIBYTES;
    optCon = poptGetContext("pcounter", argc, argv, optionsTable, 0);
    poptSetOtherOptionHelp(optCon, "[OPTIONS] <expression>");
    while ((ret = poptGetNextOpt(optCon)) >= 0) {
        switch(ret) {
            case PACKET_SIZE_BYTES:
            case PACKET_SIZE_KIBIBYTES:
            case PACKET_SIZE_MEBIBYTES:
            case PACKET_SIZE_GIBIBYTES:
                if (bytes_unit_selected) {
                    fprintf(stderr, "Option error `%s' - you already specified units\n",
                            poptBadOption(optCon, POPT_BADOPTION_NOALIAS));
                    poptFreeContext(optCon);
                    exit(1);
                }
                state.packet_size_units = ret;
                bytes_unit_selected = true;
                break;
            case CAPTURE_LIVE:
            case CAPTURE_OFFLINE:
                if (op_type != 0) {
                    /* capture type already defined */
                    fputs("Error: you already specified another capture type\n", stderr);
                    poptFreeContext(optCon);
                    exit(1);
                }
                op_type = ret;
                break;
        }
    }
    if (op_type == 0) {
        /* use live capture by default */
        op_type = CAPTURE_LIVE;
    }
    filter_size = 0;
    filters = poptGetArgs(optCon);
    while (filters != NULL && *filters != NULL) {
        const char* filter_part = *filters;

        while (*filter_part != '\0') {
            if (filter_size >= (MAX_PCAP_EXPR_LEN - 2)) {
                goto EXPRESSION_BUFFER_TOO_LARGE;
            }
            state.filter_buf[filter_size++] = *filter_part;
            filter_part++;
        }
        if (filter_size >= (MAX_PCAP_EXPR_LEN - 2)) {
            goto EXPRESSION_BUFFER_TOO_LARGE;
        }
        state.filter_buf[filter_size++] = ' ';
        filters++;
    }
    state.filter_buf[filter_size++] = '\0';
    poptFreeContext(optCon);

    if (op_type == CAPTURE_LIVE) {
        handle_live(&state);
    } else if (op_type == CAPTURE_OFFLINE) {
        handle_offline(&state);
    }
    exit(0);
EXPRESSION_BUFFER_TOO_LARGE:
    poptFreeContext(optCon);
    fputs("Filter expression to big, try smaller one\n", stderr);
    exit(1);
}
