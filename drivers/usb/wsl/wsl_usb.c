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

// Pending URB structure for tracking
struct wsl_usb_pending_urb {
	struct urb *urb;
	u32 sequence_number;
	unsigned long submit_time;
	struct list_head list;
};

// Virtual USB device structure
struct wsl_vusb_device {
	struct usb_device *udev;
	char instance_id[256];
	__u16 vendor_id;
	__u16 product_id;
	__u8 device_class;
	__u8 device_subclass;
	__u8 device_protocol;
	struct list_head list;
};

// HCD (Host Controller Driver) private data
struct wsl_usb_hcd {
	struct socket *hv_socket;
	struct task_struct *receiver_thread;
	struct list_head devices;
	struct list_head pending_urbs;
	spinlock_t lock;
	spinlock_t urb_lock;
	bool running;
	atomic_t sequence_counter;
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
		case WSL_USB_MSG_DEVICE_ATTACH:
		{
			struct wsl_usb_attach_request *attach_req;
			struct wsl_usb_attach_response attach_resp;
			struct wsl_vusb_device *vdev;

			if (payload_size < sizeof(*attach_req)) {
				pr_err("Invalid attach request size\n");
				break;
			}

			attach_req = (struct wsl_usb_attach_request *)payload;
			pr_info("Received device attach: %s\n", attach_req->instance_id);

			// Create virtual USB device
			vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
			if (!vdev) {
				attach_resp.status = -ENOMEM;
				snprintf(attach_resp.error_message, sizeof(attach_resp.error_message),
					"Failed to allocate device structure");
			} else {
				strncpy(vdev->instance_id, attach_req->instance_id, sizeof(vdev->instance_id) - 1);
				
				// Add to device list
				spin_lock(&wsl_hcd->lock);
				list_add_tail(&vdev->list, &wsl_hcd->devices);
				spin_unlock(&wsl_hcd->lock);

				attach_resp.status = 0;
				attach_resp.error_message[0] = '\0';
				
				pr_info("Virtual USB device created: %s\n", vdev->instance_id);
				
				// TODO: Register USB device with USB core
				// This would call usb_alloc_dev(), fill in device descriptor, 
				// and call usb_new_device()
			}

			// Send response
			wsl_usb_send_message(wsl_hcd->hv_socket, WSL_USB_MSG_DEVICE_ATTACH,
					    &attach_resp, sizeof(attach_resp));
			break;
		}

		case WSL_USB_MSG_DEVICE_DETACH:
		{
			struct wsl_usb_attach_request *detach_req;
			struct wsl_vusb_device *vdev, *tmp;

			if (payload_size < sizeof(*detach_req)) {
				pr_err("Invalid detach request size\n");
				break;
			}

			detach_req = (struct wsl_usb_attach_request *)payload;
			pr_info("Received device detach: %s\n", detach_req->instance_id);

			// Find and remove device
			spin_lock(&wsl_hcd->lock);
			list_for_each_entry_safe(vdev, tmp, &wsl_hcd->devices, list) {
				if (strcmp(vdev->instance_id, detach_req->instance_id) == 0) {
					list_del(&vdev->list);
					spin_unlock(&wsl_hcd->lock);
					
					// TODO: Unregister USB device
					// This would call usb_disconnect() and usb_put_dev()
					
					kfree(vdev);
					pr_info("Virtual USB device removed: %s\n", detach_req->instance_id);
					goto detach_done;
				}
			}
			spin_unlock(&wsl_hcd->lock);
			pr_warn("Device not found for detach: %s\n", detach_req->instance_id);

detach_done:
			break;
		}

		case WSL_USB_MSG_URB_RESPONSE:
		{
			struct wsl_usb_urb_response *urb_resp;
			struct wsl_usb_pending_urb *pending, *tmp;
			struct urb *urb = NULL;
			u8 *response_data;
			u32 response_data_size;
			int status;
			bool found = false;
			
			if (payload_size < sizeof(*urb_resp)) {
				pr_err("Invalid URB response size\n");
				break;
			}

			urb_resp = (struct wsl_usb_urb_response *)payload;
			response_data = (u8*)payload + sizeof(*urb_resp);
			response_data_size = payload_size - sizeof(*urb_resp);
			
			// Find pending URB by sequence number (matches header.sequence_number)
			spin_lock(&wsl_hcd->urb_lock);
			list_for_each_entry_safe(pending, tmp, &wsl_hcd->pending_urbs, list) {
				if (pending->sequence_number == header.sequence_number) {
					urb = pending->urb;
					list_del(&pending->list);
					kfree(pending);
					found = true;
					break;
				}
			}
			spin_unlock(&wsl_hcd->urb_lock);

			if (!found) {
				pr_warn("URB response for unknown sequence: %u\n", header.sequence_number);
				break;
			}

			if (!urb) {
				pr_err("NULL URB in pending list\n");
				break;
			}

			// Map Windows status to Linux error code
			if (urb_resp->status == 0) {
				status = 0;
			} else {
				// Windows error codes -> Linux error codes
				// This is simplified; production code needs complete mapping
				switch (urb_resp->status) {
				case 0xC0000001: // STATUS_UNSUCCESSFUL
					status = -EIO;
					break;
				case 0xC000009A: // STATUS_INSUFFICIENT_RESOURCES
					status = -ENOMEM;
					break;
				case 0xC0000120: // STATUS_CANCELLED
					status = -ECONNRESET;
					break;
				case 0xC0000011: // STATUS_END_OF_FILE
					status = -EPIPE;
					break;
				case 0x00000103: // STATUS_PENDING
					status = -EINPROGRESS;
					break;
				default:
					status = -EIO;
					break;
				}
			}

			// Copy response data for IN transfers
			if (usb_pipein(urb->pipe) && response_data_size > 0 && urb->transfer_buffer) {
				u32 copy_size = min((u32)urb->transfer_buffer_length, response_data_size);
				memcpy(urb->transfer_buffer, response_data, copy_size);
				urb->actual_length = copy_size;
			} else {
				urb->actual_length = urb_resp->transferred_length;
			}

			pr_debug("URB completed: seq=%u, status=%d, actual_len=%u\n",
				 header.sequence_number, status, urb->actual_length);

			// Complete the URB
			usb_hcd_giveback_urb(hcd, urb, status);
			break;
		}

		case WSL_USB_MSG_DEVICE_EVENT:
			// Handle device hotplug events
			pr_info("Received device event\n");
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
	INIT_LIST_HEAD(&wsl_hcd->pending_urbs);
	spin_lock_init(&wsl_hcd->lock);
	spin_lock_init(&wsl_hcd->urb_lock);
	wsl_hcd->running = true;
	atomic_set(&wsl_hcd->sequence_counter, 0);

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
	struct wsl_usb_pending_urb *pending, *tmp;

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

	// Cancel all pending URBs
	spin_lock(&wsl_hcd->urb_lock);
	list_for_each_entry_safe(pending, tmp, &wsl_hcd->pending_urbs, list) {
		list_del(&pending->list);
		if (pending->urb) {
			pending->urb->status = -ESHUTDOWN;
			usb_hcd_giveback_urb(hcd, pending->urb, -ESHUTDOWN);
		}
		kfree(pending);
	}
	spin_unlock(&wsl_hcd->urb_lock);

	hcd->state = HC_STATE_HALT;
}

// Find virtual device by USB device
static struct wsl_vusb_device *wsl_usb_find_vdev(struct wsl_usb_hcd *wsl_hcd, struct usb_device *udev)
{
	struct wsl_vusb_device *vdev;
	
	spin_lock(&wsl_hcd->lock);
	list_for_each_entry(vdev, &wsl_hcd->devices, list) {
		if (vdev->udev == udev) {
			spin_unlock(&wsl_hcd->lock);
			return vdev;
		}
	}
	spin_unlock(&wsl_hcd->lock);
	
	return NULL;
}

// Map Linux USB pipe to URB function code
static u16 wsl_usb_get_urb_function(struct urb *urb)
{
	int pipe = urb->pipe;
	
	if (usb_pipecontrol(pipe)) {
		// Check if this is a descriptor request
		if (urb->setup_packet) {
			struct usb_ctrlrequest *setup = (struct usb_ctrlrequest *)urb->setup_packet;
			if ((setup->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
			    setup->bRequest == USB_REQ_GET_DESCRIPTOR) {
				// GET_DESCRIPTOR
				u8 desc_type = setup->wValue >> 8;
				if (desc_type == USB_DT_DEVICE)
					return 0x000B; // URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE
				else if (desc_type == USB_DT_CONFIG)
					return 0x000B;
				else if (desc_type == USB_DT_STRING)
					return 0x000B;
			} else if (setup->bRequest == USB_REQ_SET_CONFIGURATION) {
				return 0x0000; // URB_FUNCTION_SELECT_CONFIGURATION
			} else if (setup->bRequest == USB_REQ_SET_INTERFACE) {
				return 0x0001; // URB_FUNCTION_SELECT_INTERFACE
			}
		}
		return 0x0008; // URB_FUNCTION_CONTROL_TRANSFER
	} else if (usb_pipebulk(pipe)) {
		return 0x0009; // URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
	} else if (usb_pipeint(pipe)) {
		return 0x0009; // URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
	} else if (usb_pipeisoc(pipe)) {
		return 0x000A; // URB_FUNCTION_ISOCH_TRANSFER
	}
	
	return 0x0008; // Default to control transfer
}

// URB enqueue - forward to Windows host
static int wsl_usb_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct wsl_usb_hcd *wsl_hcd = hcd_to_wsl_hcd(hcd);
	struct wsl_vusb_device *vdev;
	struct wsl_usb_pending_urb *pending;
	struct wsl_usb_urb_request *request;
	size_t request_size;
	size_t transfer_size;
	u32 sequence;
	int ret;
	void *request_buffer;

	if (!urb || !urb->dev) {
		pr_err("Invalid URB or device\n");
		return -EINVAL;
	}

	// Find virtual device
	vdev = wsl_usb_find_vdev(wsl_hcd, urb->dev);
	if (!vdev) {
		pr_err("Device not found for URB\n");
		return -ENODEV;
	}

	// Allocate pending URB structure
	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending)
		return -ENOMEM;

	// Generate sequence number
	sequence = atomic_inc_return(&wsl_hcd->sequence_counter);
	
	pending->urb = urb;
	pending->sequence_number = sequence;
	pending->submit_time = jiffies;

	// Add to pending list
	spin_lock(&wsl_hcd->urb_lock);
	list_add_tail(&pending->list, &wsl_hcd->pending_urbs);
	spin_unlock(&wsl_hcd->urb_lock);

	// Calculate transfer size for OUT transfers
	transfer_size = 0;
	if (usb_pipeout(urb->pipe) && urb->transfer_buffer_length > 0)
		transfer_size = urb->transfer_buffer_length;

	// Allocate request buffer
	request_size = sizeof(struct wsl_usb_urb_request) + transfer_size;
	request_buffer = kmalloc(request_size, GFP_KERNEL);
	if (!request_buffer) {
		ret = -ENOMEM;
		goto error_remove_pending;
	}

	request = (struct wsl_usb_urb_request *)request_buffer;

	// Build URB request
	memset(request, 0, sizeof(*request));
	strncpy(request->instance_id, vdev->instance_id, sizeof(request->instance_id) - 1);
	request->function = wsl_usb_get_urb_function(urb);
	request->transfer_buffer_length = urb->transfer_buffer_length;
	request->endpoint = usb_pipeendpoint(urb->pipe);
	
	// Set flags based on pipe direction
	request->flags = usb_pipein(urb->pipe) ? 0x01 : 0x00; // USBD_TRANSFER_DIRECTION_IN

	// Copy transfer buffer for OUT transfers
	if (transfer_size > 0) {
		memcpy((u8*)request_buffer + sizeof(*request), 
		       urb->transfer_buffer, 
		       transfer_size);
	}

	// Send URB request to host with sequence number
	ret = wsl_usb_send_message(wsl_hcd->hv_socket, WSL_USB_MSG_URB_REQUEST,
				   request_buffer, request_size);
	
	kfree(request_buffer);

	if (ret < 0) {
		pr_err("Failed to send URB request: %d\n", ret);
		goto error_remove_pending;
	}

	pr_debug("URB enqueued: seq=%u, func=0x%04x, ep=0x%02x, len=%u\n",
		 sequence, request->function, request->endpoint, request->transfer_buffer_length);

	// URB will be completed when response is received
	return 0;

error_remove_pending:
	spin_lock(&wsl_hcd->urb_lock);
	list_del(&pending->list);
	spin_unlock(&wsl_hcd->urb_lock);
	kfree(pending);
	return ret;
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
