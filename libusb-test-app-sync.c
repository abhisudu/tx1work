#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include "libusb.h"

#define BULK1_OUT 0x01
#define BULK1_IN  0x81

#define BUF_MALLOC             1
#define BUF_LIBUSB_MEM_ALLOC   2

static libusb_device_handle *handle;
static int iface;
static uint8_t *buf;
//static sem_t *tx_lock;

void sighandler(int signum)
{
    if(handle != NULL) {
        libusb_release_interface(handle, iface);
        libusb_close(handle);
        libusb_exit(NULL);
    }
    if(buf != NULL) {
        free(buf);
    }
}

int sync_data_transfer(libusb_device_handle *handle, uint8_t * buffer, int size)
{
    int i, rv, tx_size = 0;
    uint8_t ep_in = BULK1_IN, ep_out = BULK1_OUT;
    struct timeval start, end;
    unsigned long time_taken;

    //memset(buffer, 0x12, size);
    printf("\n b4 bulk transfer write \n");
    for(i=0;i<16;i++) {
        gettimeofday(&start, NULL);
        rv = libusb_bulk_transfer(handle, ep_out, buffer, size, &tx_size, 5000);
        gettimeofday(&end, NULL);
        if(rv) {
            perror(" libusb_bulk_transfer ");
            printf("\n transmitted size = %d ",tx_size);
        } else {
            printf("\n TX : transferred size = %d ",tx_size);
        }
        time_taken = (end.tv_sec*1000000 + end.tv_usec) - 
                      (start.tv_sec*1000000 + start.tv_usec);
        printf("\n time taken in micro secs = %ld",time_taken); 
    }
    printf(" b4 bulk transfer read \n");
    
    gettimeofday(&start, NULL);
    rv = libusb_bulk_transfer(handle, ep_in, buffer, size, &tx_size, 20000);
    gettimeofday(&end, NULL);
    if(rv) {
        printf(" transfer : received size = %d rv : %d \n",tx_size, rv);
    } else {
        printf("\n RX : transferred size = %d ",tx_size); 
    }
    time_taken = (end.tv_sec*1000000 + end.tv_usec) - 
                      (start.tv_sec*1000000 + start.tv_usec);
    printf("\n time taken in micro secs = %ld",time_taken);
    return tx_size;
}

void *txfunc_one(void *arg)
{
    int rv,size;
    printf("\n thread one started ");
    size = 8*1024*1024;
    buf = libusb_dev_mem_alloc(handle, size);
    if(buf == NULL) {
        printf("\n libusb dev mem alloc : NULL "); 
        buf = malloc(size);
        if(buf == NULL) {
            perror("\n malloc ");
            goto exit;
        }
        //sem_wait(&tx_lock);
        rv = sync_data_transfer(handle, buf, size);
        //sem_post(&tx_lock);
        free(buf);
    } else {
        //sem_wait(&tx_lock);
        rv = sync_data_transfer(handle, buf, size);
        //sem_post(&tx_lock);
        libusb_dev_mem_free(handle, buf, size);
    }
exit:
    libusb_release_interface(handle, iface);
    libusb_close(handle);
    libusb_exit(NULL);
    pthread_exit("txfunc_one done");
}

void *txfunc_two(void *arg)
{
    int rv,size;

    printf("\n thread two started ");
    size = 8*1024*1024;
    buf = libusb_dev_mem_alloc(handle, size);
    if(buf == NULL) {
        printf("\n libusb dev mem alloc : NULL "); 
        buf = malloc(size);
        if(buf == NULL) {
            perror("\n malloc ");
            goto exit;
        }
        //sem_wait(&tx_lock);
        rv = sync_data_transfer(handle, buf, size);
        //sem_post(&tx_lock);
        free(buf);
    } else {
        //sem_wait(&tx_lock);
        rv = sync_data_transfer(handle, buf, size);
        //sem_post(&tx_lock);
        libusb_dev_mem_free(handle, buf, size);
    }
exit:
    libusb_release_interface(handle, iface);
    libusb_close(handle);
    libusb_exit(NULL);
    pthread_exit("txfunc_two done");
}

int main(void)
{
    int i, rv, devspeed;
    libusb_device *dev;
    struct libusb_config_descriptor *conf_desc;
    struct sigaction act;
    pthread_t thread_one, thread_two;
    void *thread_result;

    printf("\n libusb test app started \n");
    rv = libusb_init(NULL);
    if(rv < 0) {
        perror("\n libusb_init failed ");
        return rv;
    }
    handle = libusb_open_device_with_vid_pid(NULL, 0xaa, 0xbb);
    if(handle == NULL) {
        perror("\n libusb open device ");
        libusb_exit(NULL);
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
  
    /*rv = sem_init(&tx_lock, 0, 0);
    if(rv != 0) {
        perror("\nsemaphore initialization failed");
        goto exit;
    }*/

    rv = pthread_create(&thread_one, NULL, txfunc_one, NULL);
    if(rv != 0) {
       perror("\nThread one creation failed");
       goto exit;
    }
    rv = pthread_create(&thread_two, NULL, txfunc_two, NULL);
    if(rv != 0) {
       perror("\nThread two creation failed");
    }
    rv = pthread_join(thread_one, &thread_result);
    if(rv != 0) {
        perror("pthread_join");
    }  
    rv = pthread_join(thread_two, &thread_result);
    if(rv != 0) {
        perror("pthread_join");
    }
    /*sem_destroy(&tx_lock);*/
    printf(" exiting \n"); 
    
exit:
    libusb_release_interface(handle, iface);
    libusb_close(handle);
    libusb_exit(NULL);
    return 0;
}
