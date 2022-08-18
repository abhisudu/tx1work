// SPDX-License-Identifier: GPL-2.0+
/*
 * modified f_loopback.c - USB peripheral loopback configuration driver
 *
 * Copyright (C) 2003-2008 David Brownell
 * Copyright (C) 2008 by Nokia Corporation
 */

/* #define VERBOSE_DEBUG */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/usb/composite.h>
#include<linux/init.h>
#include<linux/string.h>
#include "g_zero.h"
#include "u_f.h"

struct register_read_payload {
	uint32_t reg_id;
	uint32_t offset;
}*rr;
struct register_write_payload {
        uint32_t reg_id;
        uint32_t offset;
        uint32_t data;
}*rw;

typedef struct {
    uint32_t   bytes;       // size of data in bytes
    uint8_t    type;        // descriptor type
    uint8_t    cmd;         // command bits
    uint16_t   id_lo;       // descriptor id bits 0-15
    uint32_t   addr_lo;     // physical address bits 0-31
    uint16_t   addr_hi;     // physical address bits 32-47
    uint16_t   id_hi;       // descriptor id bits 16-31
    uint32_t   cmpl_error;  // error dword from completion bytes
    uint32_t   cmpl_time;   // time of completion in NP local units
    uint32_t   desc_count;  // count of completed descs till now
    uint32_t   rsvd;        // not being used for now
} __attribute__((packed)) MDMA_DATA_DESC;


extern uint32_t mythic_dev_read(uint32_t *buf, size_t len, uint32_t offset);
extern int mythic_dev_write(uint32_t *buf1, size_t len, uint32_t offset);
extern MDMA_DATA_DESC * mythic_set_desc(uint64_t *data, uint32_t size, uint32_t desc_id, uint8_t dtype, uint8_t cmd);
extern int test_check(void);

static void loopback_complete(struct usb_ep *ep, struct usb_request *req);

static uint32_t req_state;

static struct file *fp;
static inline struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    int err = 0;

    filp = filp_open(path, flags, rights);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

static inline void file_close(struct file *file) 
{
    filp_close(file, NULL);
}

static inline int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    int ret;

    ret = kernel_read(file, data, size, &offset);

    return ret;
} 

static inline int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    int ret;

    ret = kernel_write(file, data, size, &offset);

    return ret;
}

static inline int file_sync(struct file *file) 
{
    vfs_fsync(file, 0);
    return 0;
}

struct usb_request *alloc_ep_req(struct usb_ep *ep, size_t len)
{
	struct usb_request      *req;

	req = usb_ep_alloc_request(ep, GFP_ATOMIC);
	if (req) {
		req->length = usb_endpoint_dir_out(ep->desc) ?
			usb_ep_align(ep, len) : len;
		req->buf = kmalloc(req->length, GFP_ATOMIC);
		if (!req->buf) {
			usb_ep_free_request(ep, req);
			req = NULL;
		}
	}
	return req;
}
/*
 * LOOPBACK FUNCTION ... a testing vehicle for USB peripherals,
 *
 * This takes messages of various sizes written OUT to a device, and loops
 * them back so they can be read IN from it.  It has been used by certain
 * test applications.  It supports limited testing of data queueing logic.
 */
struct f_loopback {
	struct usb_function	function;

	struct usb_ep		*in1_ep;
	struct usb_ep		*out1_ep;
    	struct usb_ep		*in2_ep;
	struct usb_ep		*out2_ep;

	unsigned                qlen;
	unsigned                buflen;
        spinlock_t              queue_lock;
};

static inline struct f_loopback *func_to_loop(struct usb_function *f)
{
	return container_of(f, struct f_loopback, function);
}

/*-------------------------------------------------------------------------*/

static struct usb_interface_descriptor loopback_intf = {
	.bLength =		sizeof(loopback_intf),
	.bDescriptorType =	USB_DT_INTERFACE,

	.bNumEndpoints =	4,
	.bInterfaceClass =	USB_CLASS_VENDOR_SPEC,
	/* .iInterface = DYNAMIC */
};

/* full speed support: */

static struct usb_endpoint_descriptor fs_loop_source1_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};
static struct usb_endpoint_descriptor fs_loop_source2_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor fs_loop_sink1_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};
static struct usb_endpoint_descriptor fs_loop_sink2_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_loopback_descs[] = {
	(struct usb_descriptor_header *) &loopback_intf,
	(struct usb_descriptor_header *) &fs_loop_sink1_desc,
	(struct usb_descriptor_header *) &fs_loop_source1_desc,
    	(struct usb_descriptor_header *) &fs_loop_sink2_desc,
	(struct usb_descriptor_header *) &fs_loop_source2_desc,
	NULL,
};

/* high speed support: */

static struct usb_endpoint_descriptor hs_loop_source1_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};
static struct usb_endpoint_descriptor hs_loop_source2_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_loop_sink1_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};
static struct usb_endpoint_descriptor hs_loop_sink2_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_loopback_descs[] = {
	(struct usb_descriptor_header *) &loopback_intf,
	(struct usb_descriptor_header *) &hs_loop_source1_desc,
	(struct usb_descriptor_header *) &hs_loop_sink1_desc,
    	(struct usb_descriptor_header *) &hs_loop_source2_desc,
	(struct usb_descriptor_header *) &hs_loop_sink2_desc,
	NULL,
};

/* super speed support: */

static struct usb_endpoint_descriptor ss_loop_source1_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};
static struct usb_endpoint_descriptor ss_loop_source2_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_loop_source_comp1_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};
static struct usb_ss_ep_comp_descriptor ss_loop_source_comp2_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};

static struct usb_endpoint_descriptor ss_loop_sink1_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};
static struct usb_endpoint_descriptor ss_loop_sink2_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_loop_sink_comp1_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};
static struct usb_ss_ep_comp_descriptor ss_loop_sink_comp2_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};

static struct usb_descriptor_header *ss_loopback_descs[] = {
	(struct usb_descriptor_header *) &loopback_intf,
	(struct usb_descriptor_header *) &ss_loop_source1_desc,
	(struct usb_descriptor_header *) &ss_loop_source_comp1_desc,
	(struct usb_descriptor_header *) &ss_loop_sink1_desc,
	(struct usb_descriptor_header *) &ss_loop_sink_comp1_desc,
    	(struct usb_descriptor_header *) &ss_loop_source2_desc,
	(struct usb_descriptor_header *) &ss_loop_source_comp2_desc,
	(struct usb_descriptor_header *) &ss_loop_sink2_desc,
	(struct usb_descriptor_header *) &ss_loop_sink_comp2_desc,
	NULL,
};

/* function-specific strings: */

static struct usb_string strings_loopback[] = {
	[0].s = "loop input to output",
	{  }			/* end of list */
};

static struct usb_gadget_strings stringtab_loop = {
	.language	= 0x0409,	/* en-us */
	.strings	= strings_loopback,
};

static struct usb_gadget_strings *loopback_strings[] = {
	&stringtab_loop,
	NULL,
};

/*-------------------------------------------------------------------------*/

static int loopback_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_loopback	*loop = func_to_loop(f);
	int			id;
	int ret;

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	loopback_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return id;
	strings_loopback[0].id = id;
	loopback_intf.iInterface = id;

	/* allocate endpoints */

	loop->in1_ep = usb_ep_autoconfig(cdev->gadget, &fs_loop_source1_desc);
	if (!loop->in1_ep) {
autoconf_fail1:
		ERROR(cdev, "%s: can't autoconfigure on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}
    	loop->in2_ep = usb_ep_autoconfig(cdev->gadget, &fs_loop_source2_desc);
	if (!loop->in2_ep) {
autoconf_fail2:
		ERROR(cdev, "%s: can't autoconfigure on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	loop->out1_ep = usb_ep_autoconfig(cdev->gadget, &fs_loop_sink1_desc);
	if (!loop->out1_ep)
		goto autoconf_fail1;
    	loop->out2_ep = usb_ep_autoconfig(cdev->gadget, &fs_loop_sink2_desc);
	if (!loop->out2_ep)
		goto autoconf_fail2;

        printk("\n source 1 EP addr = %d",fs_loop_source1_desc.bEndpointAddress);
        printk("\n sink 1 EP addr = %d",fs_loop_sink1_desc.bEndpointAddress);

	/* support high speed hardware */
	hs_loop_source1_desc.bEndpointAddress =
		fs_loop_source1_desc.bEndpointAddress;
	hs_loop_sink1_desc.bEndpointAddress = fs_loop_sink1_desc.bEndpointAddress;
    	hs_loop_source2_desc.bEndpointAddress =
		fs_loop_source2_desc.bEndpointAddress;
	hs_loop_sink2_desc.bEndpointAddress = fs_loop_sink2_desc.bEndpointAddress;

	/* support super speed hardware */
	ss_loop_source1_desc.bEndpointAddress =
		fs_loop_source1_desc.bEndpointAddress;
	ss_loop_sink1_desc.bEndpointAddress = fs_loop_sink1_desc.bEndpointAddress;
    	ss_loop_source2_desc.bEndpointAddress =
		fs_loop_source2_desc.bEndpointAddress;
	ss_loop_sink2_desc.bEndpointAddress = fs_loop_sink2_desc.bEndpointAddress;

	ret = usb_assign_descriptors(f, fs_loopback_descs, hs_loopback_descs,
			ss_loopback_descs, NULL); //instead of NULL pass structure ss_
	if (ret)
		return ret;

	DBG(cdev, "%s speed %s: IN1/%s, OUT1/%s, IN2/%s, OUT2/%s\n",
	    (gadget_is_superspeed(c->cdev->gadget) ? "super" :
	     (gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full")),
			f->name, loop->in1_ep->name, loop->out1_ep->name,loop->in2_ep->name, loop->out2_ep->name);
	return 0;
}

static void lb_free_func(struct usb_function *f)
{
	struct f_lb_opts *opts;

	opts = container_of(f->fi, struct f_lb_opts, func_inst);

	mutex_lock(&opts->lock);
	opts->refcnt--;
	mutex_unlock(&opts->lock);

	usb_free_all_descriptors(f);
	kfree(func_to_loop(f));
}

static inline struct usb_request *lb_alloc_ep_req(struct usb_ep *ep, int len)
{
	return alloc_ep_req(ep, len);
}

static int alloc_lb_requests(struct usb_composite_dev *cdev,
			  struct f_loopback *loop)
{
    struct usb_request *bulkinreq, *bulkoutreq;
    int rv;    
    static uint32_t data;

    bulkoutreq = lb_alloc_ep_req(loop->out1_ep, 65536);
    if(bulkoutreq == NULL) {
        ERROR(cdev, "lb_alloc_ep req failed\n");
        return -ENOMEM;
    }
    bulkoutreq->complete = loopback_complete;
   
    /* ep queue for returning transfer descriptor and/or data when polled */ 
    bulkinreq = usb_ep_alloc_request(loop->in1_ep, GFP_ATOMIC);
    if(bulkinreq == NULL) {
        ERROR(cdev, "usb ep alloc req failed\n");
        return -ENOMEM;
    }
    bulkinreq->buf = bulkoutreq->buf;
  /* for simplicity, first 4 bytes are overwritten with transfer descriptor */ 
    data = (0x10 << 24) | 8192;
    memcpy(bulkinreq->buf, &data, sizeof(data));
    bulkinreq->complete = loopback_complete;
    bulkinreq->length = 4;
    bulkinreq->zero = 0;
    
    bulkinreq->context = bulkoutreq;
    bulkoutreq->context = bulkinreq;

    bulkoutreq->length = 65536;
    
    rv = usb_ep_queue(loop->out1_ep, bulkoutreq, GFP_ATOMIC);
    if(rv < 0) {
        ERROR(cdev, "bulk EP OUT req failed \n");
    }
    rv = usb_ep_queue(loop->in1_ep, bulkinreq, GFP_ATOMIC);
    if(rv < 0) {
        ERROR(cdev, "bulk EP IN req failed \n");
    }
    req_state = 1;
    return rv;
}

static void loopback_complete(struct usb_ep *ep, struct usb_request *req)
{
    struct f_loopback  *loop = ep->driver_data;
    int status = req->status;
    int rv;
    uint32_t *dataptr;
    struct usb_request *in1_req, *out1_req;
    unsigned long flags;

    switch (status) {
    case 0:
        if(ep == loop->in1_ep) {
            if(req_state == 1) {
                req->length = 65536;
                req_state = 2;
                
            } else if(req_state == 3) {
                req->length = 4;
                req_state = 1;
            }
            spin_lock_irqsave(&loop->queue_lock, flags); 
            rv = usb_ep_queue(loop->in1_ep, req, GFP_ATOMIC);
            spin_unlock_irqrestore(&loop->queue_lock, flags);
            if(rv < 0) {
                printk("\n -- bulk EP IN req failed \n");
            }
        } else if(ep == loop->out1_ep) {
            in1_req = req->context; 
            in1_req->length = req->actual; 
            in1_req->zero = ((req->actual % 512) == 0);
            spin_lock_irqsave(&loop->queue_lock, flags); 
            rv = usb_ep_queue(loop->out1_ep, req, GFP_ATOMIC);
            spin_unlock_irqrestore(&loop->queue_lock, flags);
            if(rv < 0) {
                printk("\n bulk EP OUT req failed \n");
            }
            req_state = 3; 
        }
    break;
    default:
	 printk("\n %s loop complete --> %d, %d/%d\n", ep->name,
				status, req->actual, req->length);
         /*fallthrough */

    /* NOTE:  since this driver doesn't maintain an explicit record
     * of requests it submitted (just maintains qlen count), we
     * rely on the hardware driver to clean up on disconnect or
     * endpoint disable.
     */
    case -ECONNABORTED:		/* hardware forced ep reset */
    case -ECONNRESET:		/* request dequeued */
    case -ESHUTDOWN:		/* disconnect from host */
free_req:
        free_ep_req(ep, req);
	return;
    }
}

static void disable_ep(struct usb_composite_dev *cdev, struct usb_ep *ep)
{
	int			value;

	value = usb_ep_disable(ep);
	if (value < 0)
		DBG(cdev, "disable %s --> %d\n", ep->name, value);
}

void disable_endpoints(struct usb_composite_dev *cdev,
		struct usb_ep *in, struct usb_ep *out,
		struct usb_ep *iso_in, struct usb_ep *iso_out)
{
	disable_ep(cdev, in);
	disable_ep(cdev, out);
	if (iso_in)
		disable_ep(cdev, iso_in);
	if (iso_out)
		disable_ep(cdev, iso_out);
}

static void disable_loopback(struct f_loopback *loop)
{
	struct usb_composite_dev	*cdev;

	cdev = loop->function.config->cdev;
	disable_endpoints(cdev, loop->in1_ep, loop->out1_ep, NULL, NULL);
	VDBG(cdev, "%s disabled\n", loop->function.name);
    	disable_endpoints(cdev, loop->in2_ep, loop->out2_ep, NULL, NULL);
	VDBG(cdev, "%s disabled\n", loop->function.name);
}

static int enable_endpoint(struct usb_composite_dev *cdev,
			   struct f_loopback *loop, struct usb_ep *ep)
{
	int					result;

	result = config_ep_by_speed(cdev->gadget, &(loop->function), ep);
	if (result)
		goto out;

	result = usb_ep_enable(ep);
	if (result < 0)
		goto out;
	ep->driver_data = loop;
	result = 0;

out:
	return result;
}

static int
enable_loopback(struct usb_composite_dev *cdev, struct f_loopback *loop)
{
	int  result = 0;

	result = enable_endpoint(cdev, loop, loop->in1_ep);
	if (result)
		goto out;

	result = enable_endpoint(cdev, loop, loop->out1_ep);
	if (result)
		goto out;
    	result = enable_endpoint(cdev, loop, loop->in2_ep);
	if (result)
		goto out;

	result = enable_endpoint(cdev, loop, loop->out2_ep);
	if (result)
		goto out;

        result = alloc_lb_requests(cdev, loop);
        if(result) {
            printk("\n alloc bulk in/out requests failed");
        }

	DBG(cdev, "%s enabled\n", loop->function.name);
	return 0;

disable_other:
	usb_ep_disable(loop->out2_ep);
    	usb_ep_disable(loop->in2_ep);
disable_lb:
	usb_ep_disable(loop->out1_ep);
    	usb_ep_disable(loop->in1_ep);
out:
	return result;
}

static int loopback_set_alt(struct usb_function *f,
		unsigned intf, unsigned alt)
{
	struct f_loopback	*loop = func_to_loop(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	//disable_loopback(loop);
	return enable_loopback(cdev, loop);
}

static void loopback_disable(struct usb_function *f)
{
	struct f_loopback	*loop = func_to_loop(f);

	disable_loopback(loop);
}

static int vendorctrlreq_setup(struct usb_function *f,
                const struct usb_ctrlrequest *ctrl)
{
    struct usb_configuration        *c = f->config;
    struct usb_request      *req = c->cdev->req;
    int                     rv;
    uint16_t                  w_index = le16_to_cpu(ctrl->wIndex);
    uint16_t                  w_value = le16_to_cpu(ctrl->wValue);
    uint16_t                  w_length = le16_to_cpu(ctrl->wLength); 
    struct f_loopback *loop;
    static uint32_t data;

    switch(ctrl->bRequest) {
    case 0x00:
        if(w_index == 18) { 
            data = 1;
        } else if(w_index == 6) {
            data = 4;
        }
        if(req && req->buf) {
            memcpy(req->buf, &data, sizeof(data));
        }
    break;
    case 0x82:
    break;
    }
    req->zero = 0;
    req->length = w_length;
    rv = usb_ep_queue(c->cdev->gadget->ep0, req, GFP_ATOMIC);
    if(rv < 0) {
        ERROR(c->cdev, "vendor specific EP0 req failed \n");
    }
    return 0;
}

static struct usb_function *loopback_alloc(struct usb_function_instance *fi)
{
	struct f_loopback	*loop;
	struct f_lb_opts	*lb_opts;

	loop = kzalloc(sizeof *loop, GFP_KERNEL);
	if (!loop)
		return ERR_PTR(-ENOMEM);

	lb_opts = container_of(fi, struct f_lb_opts, func_inst);

	mutex_lock(&lb_opts->lock);
	lb_opts->refcnt++;
	mutex_unlock(&lb_opts->lock);

	loop->buflen = lb_opts->bulk_buflen;
	loop->qlen = lb_opts->qlen;
	if (!loop->qlen)
		loop->qlen = 128;

	loop->function.name = "Customlb";
	loop->function.bind = loopback_bind;
	loop->function.set_alt = loopback_set_alt;
	loop->function.disable = loopback_disable;
	loop->function.strings = loopback_strings;
        loop->function.setup = vendorctrlreq_setup;

	loop->function.free_func = lb_free_func;
        spin_lock_init(&loop->queue_lock);

	return &loop->function;
}

static inline struct f_lb_opts *to_f_lb_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_lb_opts,
			    func_inst.group);
}

static void lb_attr_release(struct config_item *item)
{
	struct f_lb_opts *lb_opts = to_f_lb_opts(item);

	usb_put_function_instance(&lb_opts->func_inst);
}

static struct configfs_item_operations lb_item_ops = {
	.release		= lb_attr_release,
};

static ssize_t f_lb_opts_qlen_show(struct config_item *item, char *page)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int result;

	mutex_lock(&opts->lock);
	result = sprintf(page, "%d\n", opts->qlen);
	mutex_unlock(&opts->lock);

	return result;
}

static ssize_t f_lb_opts_qlen_store(struct config_item *item,
				    const char *page, size_t len)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int ret;
	u32 num;

	mutex_lock(&opts->lock);
	if (opts->refcnt) {
		ret = -EBUSY;
		goto end;
	}

	ret = kstrtou32(page, 0, &num);
	if (ret)
		goto end;

	opts->qlen = num;
	ret = len;
end:
	mutex_unlock(&opts->lock);
	return ret;
}

CONFIGFS_ATTR(f_lb_opts_, qlen);

static ssize_t f_lb_opts_bulk_buflen_show(struct config_item *item, char *page)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int result;

	mutex_lock(&opts->lock);
	result = sprintf(page, "%d\n", opts->bulk_buflen);
	mutex_unlock(&opts->lock);

	return result;
}

static ssize_t f_lb_opts_bulk_buflen_store(struct config_item *item,
				    const char *page, size_t len)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int ret;
	u32 num;

	mutex_lock(&opts->lock);
	if (opts->refcnt) {
		ret = -EBUSY;
		goto end;
	}

	ret = kstrtou32(page, 0, &num);
	if (ret)
		goto end;

	opts->bulk_buflen = num;
	ret = len;
end:
	mutex_unlock(&opts->lock);
	return ret;
}

CONFIGFS_ATTR(f_lb_opts_, bulk_buflen);

static struct configfs_attribute *lb_attrs[] = {
	&f_lb_opts_attr_qlen,
	&f_lb_opts_attr_bulk_buflen,
	NULL,
};

static const struct config_item_type lb_func_type = {
	.ct_item_ops    = &lb_item_ops,
	.ct_attrs	= lb_attrs,
	.ct_owner       = THIS_MODULE,
};

static void lb_free_instance(struct usb_function_instance *fi)
{
	struct f_lb_opts *lb_opts;

	lb_opts = container_of(fi, struct f_lb_opts, func_inst);
	kfree(lb_opts);
}

static struct usb_function_instance *loopback_alloc_instance(void)
{
	struct f_lb_opts *lb_opts;

	lb_opts = kzalloc(sizeof(*lb_opts), GFP_KERNEL);
	if (!lb_opts)
		return ERR_PTR(-ENOMEM);
	mutex_init(&lb_opts->lock);
	lb_opts->func_inst.free_func_inst = lb_free_instance;
	lb_opts->bulk_buflen = GZERO_BULK_BUFLEN;
	lb_opts->qlen = GZERO_QLEN;

	config_group_init_type_name(&lb_opts->func_inst.group, "",
				    &lb_func_type);

	return  &lb_opts->func_inst;
}
DECLARE_USB_FUNCTION(Customlb, loopback_alloc_instance, loopback_alloc);

int __init lb_modinit(void)
{
	printk("loaded custom_lb module\n");
	return usb_function_register(&Customlbusb_func);
}

void __exit lb_modexit(void)
{
	printk("custom_lb module unloaded\n");
	usb_function_unregister(&Customlbusb_func);
}
module_init(lb_modinit);
module_exit(lb_modexit);
MODULE_LICENSE("GPL");
