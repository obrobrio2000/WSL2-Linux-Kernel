// SPDX-License-Identifier: GPL-2.0
/*
 * WSL USB Passthrough Driver
 *
 * USB device passthrough over Hyper-V sockets for WSL2.
 * This driver receives USB traffic from the Windows host via hvsocket
 * and emulates USB devices in the Linux guest.
 *
 * Copyright (c) Microsoft Corporation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/vm_sockets.h>
#include <net/sock.h>

#define DRIVER_NAME "wsl_usb"
#define DRIVER_DESC "WSL USB Passthrough Driver"
#define DRIVER_VERSION "1.0"

// Protocol constants (must match Windows side)
#define WSL_USB_PORT 0x5553422 // 'USB' in hex

// Message types
enum wsl_usb_msg_type {
	WSL_USB_MSG_DEVICE_ENUM = 1,
	WSL_USB_MSG_DEVICE_ATTACH = 2,
	WSL_USB_MSG_DEVICE_DETACH = 3,
	WSL_USB_MSG_URB_REQUEST = 4,
	WSL_USB_MSG_URB_RESPONSE = 5,
	WSL_USB_MSG_DEVICE_EVENT = 6,
	WSL_USB_MSG_ERROR = 0xFF
};

// Protocol structures
struct wsl_usb_msg_header {
	__u32 type;
	__u32 payload_size;
	__u32 sequence_number;
	__u32 reserved;
} __packed;

struct wsl_usb_device_info {
	char instance_id[256];
	char device_desc[256];
	__u16 vendor_id;
	__u16 product_id;
	__u16 bcd_device;
	__u8 device_class;
	__u8 device_subclass;
	__u8 device_protocol;
	__u8 configuration_count;
	__u8 current_configuration;
	__u8 is_attached;
} __packed;

struct wsl_usb_attach_request {
	char instance_id[256];
} __packed;

struct wsl_usb_attach_response {
	__u32 status;
	char error_message[256];
} __packed;

struct wsl_usb_urb_request {
	char instance_id[256];
	__u16 function;
	__u16 reserved;
	__u32 flags;
	__u32 transfer_buffer_length;
	__u8 endpoint;
	__u8 reserved2[3];
	/* Followed by transfer buffer data */
} __packed;

struct wsl_usb_urb_response {
	__u32 status;
	__u32 transferred_length;
	/* Followed by response data */
} __packed;

// Virtual USB device structure
struct wsl_vusb_device {
	struct usb_device *udev;
	char instance_id[256];
	__u16 vendor_id;
	__u16 product_id;
	struct list_head list;
};

// HCD (Host Controller Driver) private data
struct wsl_usb_hcd {
	struct socket *hv_socket;
	struct task_struct *receiver_thread;
	struct list_head devices;
	spinlock_t lock;
	bool running;
};

static struct platform_device *wsl_usb_platform_device;

// Forward declarations
static int wsl_usb_hcd_start(struct usb_hcd *hcd);
static void wsl_usb_hcd_stop(struct usb_hcd *hcd);
static int wsl_usb_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags);
static int wsl_usb_hcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status);

// HCD operations
static const struct hc_driver wsl_usb_hc_driver = {
	.description = DRIVER_DESC,
	.product_desc = "WSL USB Virtual Host Controller",
	.hcd_priv_size = sizeof(struct wsl_usb_hcd),
	.flags = HCD_USB2,

	/* Basic lifecycle operations */
	.start = wsl_usb_hcd_start,
	.stop = wsl_usb_hcd_stop,

	/* URB operations */
	.urb_enqueue = wsl_usb_hcd_urb_enqueue,
	.urb_dequeue = wsl_usb_hcd_urb_dequeue,

	/* Root hub operations would go here */
};

// Send message to Windows host
static int wsl_usb_send_message(struct socket *sock, enum wsl_usb_msg_type type,
				const void *payload, u32 payload_size)
{
	struct wsl_usb_msg_header header;
	struct kvec iov[2];
	struct msghdr msg;
	int ret;

	if (!sock)
		return -EINVAL;

	header.type = type;
	header.payload_size = payload_size;
	header.sequence_number = 0; // Should be tracked
	header.reserved = 0;

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);

	if (payload_size > 0 && payload) {
		iov[1].iov_base = (void *)payload;
		iov[1].iov_len = payload_size;
		ret = kernel_sendmsg(sock, &msg, iov, 2, sizeof(header) + payload_size);
	} else {
		ret = kernel_sendmsg(sock, &msg, iov, 1, sizeof(header));
	}

	return ret < 0 ? ret : 0;
}

// Receive message from Windows host
static int wsl_usb_receive_message(struct socket *sock, struct wsl_usb_msg_header *header,
				   void **payload, u32 *payload_size)
{
	struct kvec iov;
	struct msghdr msg;
	int ret;

	if (!sock || !header)
		return -EINVAL;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = header;
	iov.iov_len = sizeof(*header);

	ret = kernel_recvmsg(sock, &msg, &iov, 1, sizeof(*header), MSG_WAITALL);
	if (ret != sizeof(*header))
		return ret < 0 ? ret : -EIO;

	*payload = NULL;
	*payload_size = 0;

	if (header->payload_size > 0) {
		*payload = kmalloc(header->payload_size, GFP_KERNEL);
		if (!*payload)
			return -ENOMEM;

		iov.iov_base = *payload;
		iov.iov_len = header->payload_size;

		ret = kernel_recvmsg(sock, &msg, &iov, 1, header->payload_size, MSG_WAITALL);
		if (ret != header->payload_size) {
			kfree(*payload);
			*payload = NULL;
			return ret < 0 ? ret : -EIO;
		}

		*payload_size = header->payload_size;
	}

	return 0;
}

// Receiver thread that handles messages from Windows
static int wsl_usb_receiver_thread(void *data)
{
	struct usb_hcd *hcd = data;
	struct wsl_usb_hcd *wsl_hcd = hcd_to_wsl_hcd(hcd);
	struct wsl_usb_msg_header header;
	void *payload = NULL;
	u32 payload_size;
	int ret;

	pr_info("WSL USB receiver thread started\n");

	while (!kthread_should_stop() && wsl_hcd->running) {
		ret = wsl_usb_receive_message(wsl_hcd->hv_socket, &header, &payload, &payload_size);
		if (ret < 0) {
			if (ret == -EINTR || ret == -EAGAIN)
				continue;
			pr_err("Failed to receive message: %d\n", ret);
			break;
		}

		// Process message based on type
		switch (header.type) {
		case WSL_USB_MSG_URB_RESPONSE:
			// Handle URB response
			if (payload) {
				// Complete pending URB
				// This would match sequence number to pending URB and complete it
			}
			break;

		case WSL_USB_MSG_DEVICE_EVENT:
			// Handle device hotplug events
			break;

		default:
			pr_warn("Unknown message type: %d\n", header.type);
			break;
		}

		if (payload) {
			kfree(payload);
			payload = NULL;
		}
	}

	pr_info("WSL USB receiver thread stopped\n");
	return 0;
}

// Connect to Windows USB service via Hyper-V socket
static int wsl_usb_connect_to_host(struct wsl_usb_hcd *wsl_hcd)
{
	struct sockaddr_vm addr;
	int ret;

	ret = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &wsl_hcd->hv_socket);
	if (ret < 0) {
		pr_err("Failed to create vsock: %d\n", ret);
		return ret;
	}

	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = VMADDR_CID_HOST;
	addr.svm_port = WSL_USB_PORT;

	ret = kernel_connect(wsl_hcd->hv_socket, (struct sockaddr *)&addr, sizeof(addr), 0);
	if (ret < 0) {
		pr_err("Failed to connect to host USB service: %d\n", ret);
		sock_release(wsl_hcd->hv_socket);
		wsl_hcd->hv_socket = NULL;
		return ret;
	}

	pr_info("Connected to Windows USB service\n");
	return 0;
}

// HCD start
static int wsl_usb_hcd_start(struct usb_hcd *hcd)
{
	struct wsl_usb_hcd *wsl_hcd = hcd_to_wsl_hcd(hcd);
	int ret;

	pr_info("Starting WSL USB HCD\n");

	INIT_LIST_HEAD(&wsl_hcd->devices);
	spin_lock_init(&wsl_hcd->lock);
	wsl_hcd->running = true;

	// Connect to Windows host
	ret = wsl_usb_connect_to_host(wsl_hcd);
	if (ret < 0)
		return ret;

	// Start receiver thread
	wsl_hcd->receiver_thread = kthread_run(wsl_usb_receiver_thread, hcd, "wsl_usb_recv");
	if (IS_ERR(wsl_hcd->receiver_thread)) {
		ret = PTR_ERR(wsl_hcd->receiver_thread);
		pr_err("Failed to start receiver thread: %d\n", ret);
		sock_release(wsl_hcd->hv_socket);
		wsl_hcd->hv_socket = NULL;
		return ret;
	}

	hcd->state = HC_STATE_RUNNING;
	return 0;
}

// HCD stop
static void wsl_usb_hcd_stop(struct usb_hcd *hcd)
{
	struct wsl_usb_hcd *wsl_hcd = hcd_to_wsl_hcd(hcd);

	pr_info("Stopping WSL USB HCD\n");

	wsl_hcd->running = false;

	if (wsl_hcd->receiver_thread) {
		kthread_stop(wsl_hcd->receiver_thread);
		wsl_hcd->receiver_thread = NULL;
	}

	if (wsl_hcd->hv_socket) {
		sock_release(wsl_hcd->hv_socket);
		wsl_hcd->hv_socket = NULL;
	}

	hcd->state = HC_STATE_HALT;
}

// URB enqueue - forward to Windows host
static int wsl_usb_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct wsl_usb_hcd *wsl_hcd = hcd_to_wsl_hcd(hcd);
	struct wsl_usb_urb_request request;
	int ret;

	// Build URB request
	memset(&request, 0, sizeof(request));
	// Fill in device instance ID from urb->dev
	request.transfer_buffer_length = urb->transfer_buffer_length;
	request.endpoint = usb_pipeendpoint(urb->pipe);

	// Send URB request to host
	ret = wsl_usb_send_message(wsl_hcd->hv_socket, WSL_USB_MSG_URB_REQUEST,
				   &request, sizeof(request));
	if (ret < 0) {
		pr_err("Failed to send URB request: %d\n", ret);
		return ret;
	}

	// URB will be completed when response is received
	return 0;
}

// URB dequeue
static int wsl_usb_hcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	// Cancel pending URB
	usb_hcd_giveback_urb(hcd, urb, status);
	return 0;
}

// Helper to convert hcd to wsl_hcd
static inline struct wsl_usb_hcd *hcd_to_wsl_hcd(struct usb_hcd *hcd)
{
	return (struct wsl_usb_hcd *)hcd->hcd_priv;
}

// Platform device probe
static int wsl_usb_probe(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	int ret;

	pr_info("Probing WSL USB platform device\n");

	hcd = usb_create_hcd(&wsl_usb_hc_driver, &pdev->dev, dev_name(&pdev->dev));
	if (!hcd) {
		pr_err("Failed to create HCD\n");
		return -ENOMEM;
	}

	ret = usb_add_hcd(hcd, 0, 0);
	if (ret) {
		pr_err("Failed to add HCD: %d\n", ret);
		usb_put_hcd(hcd);
		return ret;
	}

	device_wakeup_enable(hcd->self.controller);
	platform_set_drvdata(pdev, hcd);

	pr_info("WSL USB HCD registered\n");
	return 0;
}

// Platform device remove
static int wsl_usb_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);

	if (hcd) {
		usb_remove_hcd(hcd);
		usb_put_hcd(hcd);
	}

	pr_info("WSL USB HCD removed\n");
	return 0;
}

static struct platform_driver wsl_usb_platform_driver = {
	.probe = wsl_usb_probe,
	.remove = wsl_usb_remove,
	.driver = {
		.name = DRIVER_NAME,
	},
};

// Module init
static int __init wsl_usb_init(void)
{
	int ret;

	pr_info("Initializing WSL USB Passthrough Driver v%s\n", DRIVER_VERSION);

	// Register platform driver
	ret = platform_driver_register(&wsl_usb_platform_driver);
	if (ret) {
		pr_err("Failed to register platform driver: %d\n", ret);
		return ret;
	}

	// Create platform device
	wsl_usb_platform_device = platform_device_register_simple(DRIVER_NAME, -1, NULL, 0);
	if (IS_ERR(wsl_usb_platform_device)) {
		ret = PTR_ERR(wsl_usb_platform_device);
		pr_err("Failed to register platform device: %d\n", ret);
		platform_driver_unregister(&wsl_usb_platform_driver);
		return ret;
	}

	pr_info("WSL USB driver initialized successfully\n");
	return 0;
}

// Module exit
static void __exit wsl_usb_exit(void)
{
	pr_info("Unloading WSL USB Passthrough Driver\n");

	if (wsl_usb_platform_device) {
		platform_device_unregister(wsl_usb_platform_device);
		wsl_usb_platform_device = NULL;
	}

	platform_driver_unregister(&wsl_usb_platform_driver);

	pr_info("WSL USB driver unloaded\n");
}

module_init(wsl_usb_init);
module_exit(wsl_usb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsoft Corporation");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION(DRIVER_VERSION);
