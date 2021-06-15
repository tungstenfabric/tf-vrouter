/*
 * dpdkconf.c -- DPDK CLI configuration
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>


#include "vr_os.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#endif

#if defined(__linux__)
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#endif

#include <termios.h>
#include <sys/select.h>
#include <sys/time.h>
#include "vr_types.h"
#include "vr_message.h"
#include "vr_packet.h"
#include "vhost.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "ini_parser.h"

#define BUF_LENGTH 256

static int platform;
static void Usage(void);
static struct nl_client *cl;
static vr_info_msg_en msginfo;
static int sock_dir_set;
static bool dump_pending = false;
static char log_send[BUF_LENGTH];
static uint8_t *vr_info_inbuf;

enum opt_index {
    CONF_OPT_INDEX,
    LOG_OPT_INDEX,
    HELP_OPT_INDEX,
    SOCK_DIR_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [CONF_OPT_INDEX]         =   {"ddp",       required_argument,  NULL,        'd'},
    [LOG_OPT_INDEX]          =    {"log",      required_argument,  NULL,        'l'},
    [HELP_OPT_INDEX]        =   {"help",       no_argument,        NULL,        'h'},
    [SOCK_DIR_OPT_INDEX]    =   {"sock-dir",   required_argument,  NULL,        's'},
    [MAX_OPT_INDEX]         =   { NULL,        0,                  NULL,        0},
};

static void
Usage()
{
    printf("Usage: dpdkconf [--ddp [add|delete]]\n");
    printf("\t   [--sock-dir <sock dir>]\n");
    printf("\t   [--log list]\n");
    printf("\t   [--log <LOGTYPE-id> <1-8 LOG-LEVEL INT>]\n");
    printf("\t   [--log global <1-8 LOG-LEVEL INT>]\n");
    printf("\t   [--help]\n");

    exit(0);
}

static void
parse_long_opts(int option_index, char *opt_arg)
{
    errno = 0;
    if ((opt_arg != NULL) && (opt_arg[0] == '\0')) {
	Usage();
	return;
    }

    switch (option_index) {
        case CONF_OPT_INDEX:
            if (strcmp(opt_arg,"add") == 0) {
                msginfo = CONF_ADD_DDP;
            } else if (strcmp(opt_arg,"delete") == 0) {
                msginfo = CONF_DEL_DDP;
            } else {
                Usage();
            }
            break;

        case SOCK_DIR_OPT_INDEX:
            vr_socket_dir = opt_arg;
            break;

        case LOG_OPT_INDEX:
            if (strcmp(opt_arg,"list") == 0){
                msginfo = CONF_LOG_LIST;
            }
            else if (strlen(opt_arg)>0){
                msginfo = CONF_LOG;
                vr_info_inbuf = opt_arg;
            }
            else {
                Usage();
            }

        default:
            break;
    }

    return;
}

/*
 * Response messages to print, DDP ADD/DEL messge success or fail.
 */
static void
dpdkconf_resp_cb_process(void *s_req)
{
    int ret = 0;
    vr_info_req *resp = (vr_info_req *)s_req;
    if(resp != NULL && resp->vdu_proc_info) {
        /* Print the Message buffer(character buffer)
         * sent by vRouter(Server) */
        printf("%s", resp->vdu_proc_info);
    }

}

static void
dpdkconf_fill_nl_callbacks()
{
    nl_cb.vr_info_req_process = dpdkconf_resp_cb_process;
}

static int
vr_set_dpdkconf(struct nl_client *cl)
{
    int ret;

    ret = vr_send_ddp_req(cl, msginfo, vr_info_inbuf);
    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, true);
    if (ret <= 0)
        return ret;

    return 0;
}

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    unsigned int i = 0;
    char *space_fill=" ";
    unsigned int sock_proto = NETLINK_GENERIC;
    dpdkconf_fill_nl_callbacks();
    parse_ini_file();
    platform = get_platform();

    while ((opt = getopt_long(argc, argv, "hd:s:l:",
                    long_options, &option_index)) >= 0) {
        switch (opt) {
            case 'd':
                parse_long_opts(CONF_OPT_INDEX, optarg);
                break;

            case 's':
                sock_dir_set = 1;
                parse_long_opts(SOCK_DIR_OPT_INDEX, optarg);
                break;

            case 'l':
                if (optind == 2 && argc == 2) {
                    Usage();
                    break;
                } else if (strcmp(optarg, "list") == 0 && optind == argc) {
                    parse_long_opts(LOG_OPT_INDEX, optarg);
                    break;
                } else if (optind < argc) {
                    snprintf(log_send, sizeof(log_send), "%s %s", optarg, argv[optind]);
                    parse_long_opts(LOG_OPT_INDEX, log_send);
                    break;
                } else {
                    Usage();
                    break;
                }

            case 0:
                parse_long_opts(option_index, optarg);
                break;

            case '?':
            default:
                Usage();
        }
    }

    sock_proto = VR_NETLINK_PROTO_DEFAULT;

    if (sock_dir_set) {
        set_platform_vtest();
        /* Reinit platform variable since platform is changed to vtest now */
        platform = get_platform();
    }

    cl = vr_get_nl_client(sock_proto);
    if (!cl) {
        printf("Error registering NetLink client: %s (%d)\n",
                strerror(errno), errno);
        exit(-ENOMEM);
    }

    vr_set_dpdkconf(cl);
    return 0;
}
