#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <sys/time.h>
#include "libusb.h"

#define BULK1_OUT 0x01
#define BULK1_IN  0x81

#define NUM_ASYNC_REQUESTS      32 

static libusb_device_handle *handle;
static uint8_t *buf[NUM_ASYNC_REQUESTS];
static uint8_t *in_buf[NUM_ASYNC_REQUESTS];
static int iface;
static libusb_context *ctx;
static struct timeval async_tx_start[NUM_ASYNC_REQUESTS], async_tx_end[NUM_ASYNC_REQUESTS];
static struct timeval async_rx_start[NUM_ASYNC_REQUESTS], async_rx_end[NUM_ASYNC_REQUESTS];
int intr_flag = 0;
int completed = 0;
static int tx_count, rx_count;
static struct libusb_transfer *prev_tx;

void sighandler(int signum)
{
    if(handle != NULL) {
        libusb_release_interface(handle, iface);
        libusb_close(handle);
        libusb_exit(ctx);
    }
    intr_flag = 1; 
}

void cb_in(struct libusb_transfer *transfer)
{
    completed++;
    gettimeofday(&async_rx_end[rx_count++], NULL);
    if(prev_tx != NULL) {
        libusb_free_transfer(prev_tx);
    }
    prev_tx = transfer;
}

void cb_out(struct libusb_transfer *transfer)
{
    completed++;
    gettimeofday(&async_tx_end[tx_count++], NULL);
    if(prev_tx != NULL) {
        libusb_free_transfer(prev_tx);
    }
    prev_tx = transfer;
}

int async_data_transfer(libusb_device_handle *handle, int size)
{
    struct libusb_transfer *transfer;
    uint8_t ep_in = BULK1_IN, ep_out = BULK1_OUT;
    int i = 0, rv;

    for(i=0;i<NUM_ASYNC_REQUESTS;i++) {
        buf[i] = malloc(size);
        if(buf[i] == NULL) {
            perror("\n buf malloc ");
            return -ENOMEM;
        }
        memset(buf[i], 11, size);
        transfer = libusb_alloc_transfer(0);
        libusb_fill_bulk_transfer(transfer, handle, ep_out, buf[i], size,
                                  cb_out, NULL, 0);
        gettimeofday(&async_tx_start[i], NULL);
        rv = libusb_submit_transfer(transfer);
        if(rv) {
            perror("libusb_submit_transfer");
        }

        in_buf[i] = malloc(size);
        if(in_buf[i] == NULL) {
            perror("\n in_buf malloc ");
            return -ENOMEM;
        } 
        transfer = libusb_alloc_transfer(0);
        libusb_fill_bulk_transfer(transfer, handle, ep_in, in_buf[i], size,
                                  cb_in, NULL, 0);
        gettimeofday(&async_rx_start[i], NULL);
        rv = libusb_submit_transfer(transfer);
        if(rv) {
            perror("libusb_submit_transfer");
        }
    }
    return rv;
} 

int main(void)
{
    int i, j, rv, devspeed, size;
    libusb_device *dev;
    struct libusb_config_descriptor *conf_desc;
    struct sigaction act;
    unsigned long time_taken;

    printf("\n libusb test app started \n");
    rv = libusb_init(NULL);
    if(rv < 0) {
        perror("\n libusb_init failed ");
        return rv;
    }
    handle = libusb_open_device_with_vid_pid(ctx, 0xaa, 0xbb);
    if(handle == NULL) {
        perror("\n libusb open device ");
        libusb_exit(ctx);
        return -1; 
    }
    printf("\n libusb device opened \n");
    libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO);

    dev = libusb_get_device(handle);
    if(dev == NULL) {
        perror("\n libusb_device struct ");
    }
    devspeed = libusb_get_device_speed(dev);
    printf("\n usb device speed = %d \n",devspeed); 

    libusb_get_config_descriptor(dev, 0, &conf_desc);

    rv = libusb_kernel_driver_active(handle, iface);
    if(rv == 1) {
        if(libusb_detach_kernel_driver(handle, iface) == 0)
            printf("\nKernel driver detached for interface %d: %d\n", iface, rv);
    }
    printf("\nClaiming interface %d...\n", iface);
    rv = libusb_claim_interface(handle, iface);
    if (rv != LIBUSB_SUCCESS) {
        perror("\n claim interface Failed.");
        printf("\n error num = %d",errno);
        libusb_free_config_descriptor(conf_desc);
        goto exit;
    }
    libusb_free_config_descriptor(conf_desc);

    for(i=0;i<3;i++) {
        rv = libusb_set_interface_alt_setting(handle, iface, 0);
        if(rv) {
           perror("\n set interface ");
        } else {
           break;
        }
        sleep(1); 
    }
    act.sa_handler = sighandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);
    printf("\n after set interface");

    size = 64*1024;
    rv = async_data_transfer(handle, size);

    printf("\n waiting for async events to complete");
    while(intr_flag==0) {
        rv = libusb_handle_events_completed(ctx, NULL);
        if(rv < 0) {
            perror("libusb_handle_events_completed");
            break;
        } 
        if(completed >= (2*NUM_ASYNC_REQUESTS))
            break;
    }
    printf("\n completed = %d",completed);

    for(i=0;i<NUM_ASYNC_REQUESTS;i++) {
        rv = memcmp(buf[i], in_buf[i], size);
        if(rv) {
            printf("\n tx and rx different : rv = %d ", rv);
        } else {
            printf("\n tx and rx data matches");
        }
        time_taken = (async_tx_end[i].tv_sec*1000000 + async_tx_end[i].tv_usec) - 
                      (async_tx_start[i].tv_sec*1000000 + async_tx_start[i].tv_usec);
        printf("\n %d tx async - time taken in micro secs = %ld", i, time_taken);
        time_taken = (async_rx_end[i].tv_sec*1000000 + async_rx_end[i].tv_usec) - 
                      (async_rx_start[i].tv_sec*1000000 + async_rx_start[i].tv_usec);
        printf("\n %d rx async - time taken in micro secs = %ld", i, time_taken);
 
        free(buf[i]);
        free(in_buf[i]);
    }

    if(intr_flag == 1) {
        printf("\n caught signal intr ");
        exit(0);
    }

    printf(" exiting \n"); 
exit:
    libusb_release_interface(handle, iface);
    libusb_close(handle);
    libusb_exit(ctx);
    return 0;
}
