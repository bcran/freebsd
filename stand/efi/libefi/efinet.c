/*-
 * Copyright (c) 2001 Doug Rabson
 * Copyright (c) 2002, 2006 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <stand.h>
#include <net.h>
#include <netif.h>

#include <efi.h>
#include <efilib.h>
#include <efitcp.h>
#include "efisb.h"

static EFI_GUID sn_guid = EFI_SIMPLE_NETWORK_PROTOCOL;

static void efinet_end(struct netif *);
static ssize_t efinet_get(struct iodesc *, void **, size_t, time_t);
static void efinet_init(struct iodesc *, void *);
static int efinet_match(struct netif *, void *);
static int efinet_probe(struct netif *, void *);
static ssize_t efinet_put(struct iodesc *, void *, size_t);
static int efinet_connect(struct iodesc *);

struct netif_driver efinetif = {   
	.netif_bname = "efinet",
	.netif_match = efinet_match,
	.netif_probe = efinet_probe,
	.netif_init = efinet_init,
	.netif_connect = efinet_connect,
	.netif_get = efinet_get,
	.netif_put = efinet_put,
	.netif_end = efinet_end,
	.netif_ifs = NULL,
	.netif_nifs = 0
};

#ifdef EFINET_DEBUG
static void
dump_mode(EFI_SIMPLE_NETWORK_MODE *mode)
{
	int i;

	printf("State                 = %x\n", mode->State);
	printf("HwAddressSize         = %u\n", mode->HwAddressSize);
	printf("MediaHeaderSize       = %u\n", mode->MediaHeaderSize);
	printf("MaxPacketSize         = %u\n", mode->MaxPacketSize);
	printf("NvRamSize             = %u\n", mode->NvRamSize);
	printf("NvRamAccessSize       = %u\n", mode->NvRamAccessSize);
	printf("ReceiveFilterMask     = %x\n", mode->ReceiveFilterMask);
	printf("ReceiveFilterSetting  = %u\n", mode->ReceiveFilterSetting);
	printf("MaxMCastFilterCount   = %u\n", mode->MaxMCastFilterCount);
	printf("MCastFilterCount      = %u\n", mode->MCastFilterCount);
	printf("MCastFilter           = {");
	for (i = 0; i < mode->MCastFilterCount; i++)
		printf(" %s", ether_sprintf(mode->MCastFilter[i].Addr));
	printf(" }\n");
	printf("CurrentAddress        = %s\n",
	    ether_sprintf(mode->CurrentAddress.Addr));
	printf("BroadcastAddress      = %s\n",
	    ether_sprintf(mode->BroadcastAddress.Addr));
	printf("PermanentAddress      = %s\n",
	    ether_sprintf(mode->PermanentAddress.Addr));
	printf("IfType                = %u\n", mode->IfType);
	printf("MacAddressChangeable  = %d\n", mode->MacAddressChangeable);
	printf("MultipleTxSupported   = %d\n", mode->MultipleTxSupported);
	printf("MediaPresentSupported = %d\n", mode->MediaPresentSupported);
	printf("MediaPresent          = %d\n", mode->MediaPresent);
}
#endif



EFI_EVENT mtx;
EFI_TCP4 *tcp4 = NULL;

static void EFIAPI
connected(void *evt, void *ctx)
{
//	EFI_EVENT event = evt;
	EFI_STATUS *s = ctx;
	printf("Connected status: %d\n", *s);
	BS->SignalEvent(mtx);

}

static void EFIAPI
transmitted(void *evt, void *ctx)
{
	EFI_TCP4_IO_TOKEN *tok = ctx;
		EFI_EVENT event = evt;

//		printf("transmitted status: %d\n", tok->CompletionToken.Status);
//		printf("transmitted: %u bytes!\n", tok->Packet.TxData->DataLength);
		BS->SignalEvent(mtx);
}

static void EFIAPI
recieved(void *evt, void *ctx)
{
	EFI_TCP4_IO_TOKEN *tok = ctx;
	EFI_EVENT event = evt;

//	printf("received status: %d\n", tok->CompletionToken.Status);
//	printf("received: %u bytes!\n", tok->Packet.RxData->DataLength);
	BS->SignalEvent(mtx);
}




static int
efinet_match(struct netif *nif, void *machdep_hint)
{
	struct devdesc *dev = machdep_hint;

	printf("efinet_match\n");

	if (dev->d_unit == nif->nif_unit)
		return (1);
	return(0);
}

static int
efinet_probe(struct netif *nif, void *machdep_hint)
{

	return (0);
}

static ssize_t
efinet_put_tcp(struct iodesc *desc, void *pkt, size_t len)
{
	EFI_TCP4_IO_TOKEN iot;
	EFI_TCP4_TRANSMIT_DATA data;
	void *buf;

		EFI_STATUS status;
		unsigned long n;

	buf = malloc(len);
	data.Push = FALSE;
	data.Urgent = FALSE;
	data.DataLength = len;
	data.FragmentCount = 1;
	data.FragmentTable[0].FragmentBuffer = pkt;
	data.FragmentTable[0].FragmentLength = len;



	iot.Packet.TxData = &data;
	status = BS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, &transmitted, &iot, &iot.CompletionToken.Event);

	if (status != EFI_SUCCESS)
		printf("Faield to CreateEvent: %d\n", status);

	status = tcp4->Transmit(tcp4, &iot);
	if (status != EFI_SUCCESS)
	{
		printf("Transmit failed: %d\n", status);
	}

	status = BS->WaitForEvent(1, &mtx, &n);
	if (status != EFI_SUCCESS)
	{
		printf("BS->WaitForEvent failed: %d\n", status);
	}

	return iot.Packet.TxData->DataLength;
}

static ssize_t
efinet_put(struct iodesc *desc, void *pkt, size_t len)
{
	struct netif *nif = desc->io_netif;
	EFI_SIMPLE_NETWORK *net;
	EFI_STATUS status;
	void *buf;

	net = nif->nif_devdata;
	if (net == NULL)
		return (-1);

	if (tcp4 != NULL)
	{
		return efinet_put_tcp(desc, pkt, len);
	}

	status = net->Transmit(net, 0, len, pkt, NULL, NULL, NULL);
	if (status != EFI_SUCCESS)
		return (-1);

	/* Wait for the buffer to be transmitted */
	do {
		buf = NULL;	/* XXX Is this needed? */
		status = net->GetStatus(net, NULL, &buf);
		/*
		 * XXX EFI1.1 and the E1000 card returns a different 
		 * address than we gave.  Sigh.
		 */
	} while (status == EFI_SUCCESS && buf == NULL);

	/* XXX How do we deal with status != EFI_SUCCESS now? */
	return ((status == EFI_SUCCESS) ? len : -1);
}

static ssize_t
efinet_get_tcp(struct iodesc *desc, void **pkt, size_t len, time_t timeout)
{
	EFI_TCP4_IO_TOKEN iot;
	EFI_TCP4_RECEIVE_DATA data;
	void *buf;

		EFI_STATUS status;
		unsigned long n;

	buf = malloc(len);
	data.UrgentFlag = FALSE;
	data.DataLength = len;
	data.FragmentCount = 1;
	data.FragmentTable[0].FragmentBuffer = buf;
	data.FragmentTable[0].FragmentLength = len;



	iot.Packet.RxData = &data;
	status = BS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, &recieved, &iot, &iot.CompletionToken.Event);

	if (status != EFI_SUCCESS)
		printf("Faield to CreateEvent: %d\n", status);

	status = tcp4->Receive(tcp4, &iot);
	if (status != EFI_SUCCESS)
	{
		printf("Receive failed: %d\n", status);
	}

	status = BS->WaitForEvent(1, &mtx, &n);
	if (status != EFI_SUCCESS)
	{
		printf("BS->WaitForEvent failed: %d\n", status);
	}

	*pkt = malloc(iot.Packet.RxData->DataLength);
	memcpy(*pkt, buf, iot.Packet.RxData->DataLength);


	return iot.Packet.RxData->DataLength;
}

static ssize_t
efinet_get(struct iodesc *desc, void **pkt, size_t len, time_t timeout)
{
	struct netif *nif = desc->io_netif;
	EFI_SIMPLE_NETWORK *net;
	EFI_STATUS status;
	UINTN bufsz;
	time_t t;
	char *buf, *ptr;
	ssize_t ret = -1;

	if (tcp4 != NULL)
	{
		return efinet_get_tcp(desc, pkt, len, timeout);
	}

	net = nif->nif_devdata;
	if (net == NULL)
		return (ret);

	bufsz = net->Mode->MaxPacketSize + ETHER_HDR_LEN + ETHER_CRC_LEN;
	buf = malloc(bufsz + ETHER_ALIGN);
	if (buf == NULL)
		return (ret);
	ptr = buf + ETHER_ALIGN;

	t = getsecs();
	while ((getsecs() - t) < timeout) {
		status = net->Receive(net, NULL, &bufsz, ptr, NULL, NULL, NULL);
		if (status == EFI_SUCCESS) {
			*pkt = buf;
			ret = (ssize_t)bufsz;
			break;
		}
		if (status != EFI_NOT_READY)
			break;
	}

	if (ret == -1)
		free(buf);
	return (ret);
}



static int
efinet_connect(struct iodesc *desc)
{
	struct netif *nif = desc->io_netif;
	EFI_SERVICE_BINDING_PROTOCOL *tcp4sb = NULL;
	EFI_TCP4_IO_TOKEN token;
	EFI_TCP4_TRANSMIT_DATA data;
	EFI_TCP4_CONNECTION_TOKEN conntoken;
	EFI_TCP4_CONFIG_DATA config;
	EFI_STATUS status;
	EFI_GUID tcp4sb_guid = EFI_TCP4_SERVICE_BINDING_PROTOCOL;
	EFI_HANDLE h;

	EFI_GUID tcp4_guid = EFI_TCP4_PROTOCOL;
	int ret = -1;
	UINTN n;
	char *buf = "GET /boot/kernel/kernel HTTP/1.1\r\nUser-Agent: UefiHttpBoot/1.0\r\n\r\n";

	printf("efinet_connect, tcp4 = %p\n", tcp4);

	status = BS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, &connected, &conntoken.CompletionToken.Status, &conntoken.CompletionToken.Event);

	if (status != 0) {
		printf("Failed to CreateEvent: %d\n", status);
	}

	status = BS->CreateEvent(0, TPL_NOTIFY, NULL, NULL, &mtx);
	if (EFI_ERROR(status))
	{
		printf("Failed to create mtx event: %d\n", status);
	}


	status = tcp4->Connect(tcp4, &conntoken);

	if (EFI_ERROR(status)) {
		printf("Failed to connect: %d\n", status);
	}


	status = BS->WaitForEvent(1, &mtx, &n);
	if (EFI_ERROR(status))
	{
		printf("Faield to WaitForEvent: %d\n", status);
	}
//

#if 0
	data.Push = FALSE;
	data.Urgent = FALSE;
	data.DataLength = strlen(buf) + 1;
	data.FragmentCount = 1;
	data.FragmentTable[0].FragmentLength = strlen(buf) + 1;
	data.FragmentTable[0].FragmentBuffer = buf;

	token.Packet.TxData = &data;
	status = BS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, &transmitted, &token.CompletionToken.Status, &token.CompletionToken.Event);

	if (status != EFI_SUCCESS)
		printf("Faield to CreateEvent: %d\n", status);

	status = tcp4->Transmit(tcp4, &token);
	if (status != EFI_SUCCESS)
	{
		printf("Transmit failed: %d\n", status);
	}

	BS->WaitForEvent(1, &mtx, &n);
	
	
	EFI_TCP4_CLOSE_TOKEN close;
	close.AbortOnClose = FALSE;
	BS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, &connected, &close.CompletionToken.Status, &close.CompletionToken.Event);
#endif	
	return (0);
}

extern EFI_GUID devid;

static void
efinet_init_tcp(struct iodesc *desc, void *machdep_hint)
{

	EFI_DEVICE_PATH *imgpath;
	EFI_DEVICE_PATH *dp;
	EFI_STATUS rv;
	URI_DEVICE_PATH *uri;

	rv = BS->HandleProtocol(boot_img->DeviceHandle, &devid, (void **)&imgpath);
	
	if (!EFI_ERROR(rv)) {
		dp = imgpath;

		while (1) {
			if (IsDevicePathEndType(NextDevicePathNode(dp)))
				break;
			dp = NextDevicePathNode(dp);
		}

		if (DevicePathSubType(dp) == MSG_URI_DP) {
		        printf("%S\n", efi_devpath_name(dp));
				
			myip.s_addr = 0x0D00A8C0;
			nameip.s_addr = 0x0100A8C0;
			rootip.s_addr = 0x0100A8C0;
			swapip.s_addr = 0x0100A8C0;
			gateip.s_addr = 0x0100A8C0;

			desc->destip.s_addr = 0x0100A8C0;
			desc->myip.s_addr   = 0x0D00A8C0;
			desc->destport = 80;
			desc->myport = 0;
			desc->xid = 1;
		}
	}

	EFI_TCP4_CONFIG_DATA config;
	EFI_STATUS status;

	memset(&config, 0, sizeof(config));
	config.ControlOption = NULL;
	config.AccessPoint.UseDefaultAddress = FALSE;
	config.AccessPoint.StationPort = 0;
	config.AccessPoint.StationAddress.Addr[0] = 192;
	config.AccessPoint.StationAddress.Addr[1] = 168;
	config.AccessPoint.StationAddress.Addr[2] = 0;
	config.AccessPoint.StationAddress.Addr[3] = 13;

	config.AccessPoint.SubnetMask.Addr[0] = 255;
	config.AccessPoint.SubnetMask.Addr[1] = 255;
	config.AccessPoint.SubnetMask.Addr[2] = 255;
	config.AccessPoint.SubnetMask.Addr[3] = 0;
	

	memcpy(&config.AccessPoint.RemoteAddress.Addr, &desc->destip, sizeof(desc->destip));
	config.AccessPoint.RemotePort = desc->destport;
	config.AccessPoint.ActiveFlag = TRUE;

	printf("StationAddress = %d.%d.%d.%d\n", config.AccessPoint.StationAddress.Addr[0],config.AccessPoint.StationAddress.Addr[1],config.AccessPoint.StationAddress.Addr[2],config.AccessPoint.StationAddress.Addr[3]);
	printf("RemoteAddress = %d.%d.%d.%d\n", config.AccessPoint.RemoteAddress.Addr[0],config.AccessPoint.RemoteAddress.Addr[1],config.AccessPoint.RemoteAddress.Addr[2],config.AccessPoint.RemoteAddress.Addr[3]);

	printf("SubnetMask = %d.%d.%d.%d\n", config.AccessPoint.SubnetMask.Addr[0],config.AccessPoint.SubnetMask.Addr[1],config.AccessPoint.SubnetMask.Addr[2],config.AccessPoint.SubnetMask.Addr[3]);
	printf("RemotePort = %d\n", config.AccessPoint.RemotePort);

	printf("TCP4i *** = %p\n", tcp4);

	status = tcp4->Configure(tcp4, &config);
	if (status != EFI_SUCCESS)
	{
		printf("tcp4->Configure failed: %d\n", status);
	}

	printf("OK: TCP4 is configured (tcp4 = %p)!\n", tcp4);
}

static void
efinet_init(struct iodesc *desc, void *machdep_hint)
{
	struct netif *nif = desc->io_netif;
	EFI_SIMPLE_NETWORK *net;
	EFI_HANDLE h;
	EFI_STATUS status;
	UINT32 mask;

	printf("efinet_init\n");

	/* TODO Make it more obvious this is for TCP */
	if (nif->nif_driver->netif_ifs[nif->nif_unit].dif_private == NULL)
		return efinet_init_tcp(desc, machdep_hint);


	if (nif->nif_driver->netif_ifs[nif->nif_unit].dif_unit < 0) {
		printf("Invalid network interface %d\n", nif->nif_unit);
		return;
	}

	h = nif->nif_driver->netif_ifs[nif->nif_unit].dif_private;

	status = BS->HandleProtocol(h, &sn_guid, (VOID **)&nif->nif_devdata);
	if (status != EFI_SUCCESS) {
		printf("net%d: cannot fetch interface data (status=%lu)\n",
		    nif->nif_unit, EFI_ERROR_CODE(status));
		return;
	}

	net = nif->nif_devdata;
	if (net->Mode->State == EfiSimpleNetworkStopped) {
		status = net->Start(net);
		if (status != EFI_SUCCESS) {
			printf("net%d: cannot start interface (status=%lu)\n",
			    nif->nif_unit, EFI_ERROR_CODE(status));
			return;
		}
	}

	if (net->Mode->State != EfiSimpleNetworkInitialized) {
		status = net->Initialize(net, 0, 0);
		if (status != EFI_SUCCESS) {
			printf("net%d: cannot init. interface (status=%lu)\n",
			    nif->nif_unit, EFI_ERROR_CODE(status));
			return;
		}
	}

	mask = EFI_SIMPLE_NETWORK_RECEIVE_UNICAST |
	    EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST;

	status = net->ReceiveFilters(net, mask, 0, FALSE, 0, NULL);
	if (status != EFI_SUCCESS)
		printf("net%d: cannot set rx. filters (status=%lu)\n",
		    nif->nif_unit, EFI_ERROR_CODE(status));

#ifdef EFINET_DEBUG
	dump_mode(net->Mode);
#endif

	bcopy(net->Mode->CurrentAddress.Addr, desc->myea, 6);
	desc->xid = 1;
}

static void
efinet_end(struct netif *nif)
{
	EFI_SIMPLE_NETWORK *net = nif->nif_devdata; 

	if (net == NULL)
		return;

	net->Shutdown(net);
}

static int efinet_dev_init(void);
static int efinet_dev_print(int);

struct devsw efinet_dev = {
	.dv_name = "net",
	.dv_type = DEVT_NET,
	.dv_init = efinet_dev_init,
	.dv_strategy = NULL,		/* Will be set in efinet_dev_init */
	.dv_open = NULL,		/* Will be set in efinet_dev_init */
	.dv_close = NULL,		/* Will be set in efinet_dev_init */
	.dv_ioctl = noioctl,
	.dv_print = efinet_dev_print,
	.dv_cleanup = NULL
};

extern EFI_LOADED_IMAGE *boot_img;

static int efinet_dev_init_uri(EFI_HANDLE *boot_handle)
{
	struct netif_dif *dif;
	struct netif_stats *stats;
	
	EFI_SERVICE_BINDING_PROTOCOL *tcp4sb = NULL;
	EFI_TCP4_IO_TOKEN token;
	EFI_TCP4_TRANSMIT_DATA data;
	EFI_TCP4_CONNECTION_TOKEN conntoken;
	EFI_TCP4_CONFIG_DATA config;
	EFI_STATUS status;
	EFI_GUID tcp4sb_guid = EFI_TCP4_SERVICE_BINDING_PROTOCOL;
	EFI_HANDLE h;
	const int nifs = 1;
	int err;

	EFI_GUID tcp4_guid = EFI_TCP4_PROTOCOL;
	int ret = -1;
	UINTN n;
	EFI_HANDLE handles[2];
	extern struct devsw netdev;
	char *buf = "GET /boot/kernel/kernel HTTP/1.1\r\nUser-Agent: UefiHttpBoot/1.0\r\n\r\n";

	status = BS->LocateProtocol(&tcp4sb_guid, NULL, (VOID**)&tcp4sb);
	if (status != EFI_SUCCESS)
	{
		printf("failed to locate TCP4SB protocol: %d\n", status);
		while (1) {}
		return (-1);
	}

	status = tcp4sb->CreateChild(tcp4sb, &h);

	if (status != EFI_SUCCESS)
	{
		printf("Failed to CreateChild: %d\n", status);
		return (-1);
	}

	status = BS->OpenProtocol(h, &tcp4_guid, (VOID**)&tcp4, IH, NULL, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
	if (status != EFI_SUCCESS)
	{
		printf("Failed to open TCP4 protocol: %d\n", status);
		return (-1);
	}

	handles[0] = (EFI_HANDLE*)tcp4sb;

	handles[0] = boot_handle;
	err = efi_register_handles(&efinet_dev, handles, NULL, 1);
	if (err != 0)
		return -1;

	efinetif.netif_ifs = calloc(nifs, sizeof(struct netif_dif));
	stats = calloc(nifs, sizeof(struct netif_stats));
	if (efinetif.netif_ifs == NULL || stats == NULL) {
		free(efinetif.netif_ifs);
		free(stats);
		efinetif.netif_ifs = NULL;
		err = ENOMEM;
		return (-1);
	}
	efinetif.netif_nifs = nifs;


	dif = &efinetif.netif_ifs[0];
	dif->dif_unit = 0;
	dif->dif_nsel = 1;
	dif->dif_stats = &stats[0];
	dif->dif_private = NULL;

	efinet_dev.dv_open = netdev.dv_open;
	efinet_dev.dv_close = netdev.dv_close;
	efinet_dev.dv_strategy = netdev.dv_strategy;

	return (0);
}

static int
efinet_dev_init(void)
{
	struct netif_dif *dif;
	struct netif_stats *stats;
	EFI_DEVICE_PATH *devpath, *node;
	EFI_SIMPLE_NETWORK *net;
	EFI_HANDLE *handles, *handles2;
	EFI_STATUS status;
	UINTN sz;
	int err, i, nifs;
	extern struct devsw netdev;

	EFI_DEVICE_PATH *imgpath;
	EFI_DEVICE_PATH *dp;
	EFI_STATUS rv;

	rv = BS->HandleProtocol(boot_img->DeviceHandle, &devid, (void **)&imgpath);
	
	if (!EFI_ERROR(rv)) {
		dp = imgpath;

		while (1) {
			if (IsDevicePathEndType(NextDevicePathNode(dp)))
				break;
			dp = NextDevicePathNode(dp);
		}

		if (DevicePathSubType(dp) == MSG_URI_DP) {
		        printf("%S\n", efi_devpath_name(dp));
			EFI_HANDLE *h = efi_devpath_handle(imgpath);
			printf("h = %p\n", h);
			return efinet_dev_init_uri(h);
		}
	}

	sz = 0;
	handles = NULL;

	status = BS->LocateHandle(ByProtocol, &sn_guid, NULL, &sz, NULL);
	if (status == EFI_BUFFER_TOO_SMALL) {
		handles = (EFI_HANDLE *)malloc(sz);
		status = BS->LocateHandle(ByProtocol, &sn_guid, NULL, &sz,
		    handles);
		if (EFI_ERROR(status))
			free(handles);
	}
	if (EFI_ERROR(status))
		return (efi_status_to_errno(status));
	handles2 = (EFI_HANDLE *)malloc(sz);
	if (handles2 == NULL) {
		free(handles);
		return (ENOMEM);
	}
	nifs = 0;
	for (i = 0; i < sz / sizeof(EFI_HANDLE); i++) {
		devpath = efi_lookup_devpath(handles[i]);
		if (devpath == NULL)
			continue;
		if ((node = efi_devpath_last_node(devpath)) == NULL)
			continue;

		if (DevicePathType(node) != MESSAGING_DEVICE_PATH ||
		    DevicePathSubType(node) != MSG_MAC_ADDR_DP)
			continue;

		/*
		* Open the network device in exclusive mode. Without this
		* we will be racing with the UEFI network stack. It will
		* pull packets off the network leading to lost packets.
		*/
		status = BS->OpenProtocol(handles[i], &sn_guid, (void **)&net,
		   IH, NULL, EFI_OPEN_PROTOCOL_EXCLUSIVE);
		if (status != EFI_SUCCESS) {
			printf("Unable to open network interface %d for "
					"exclusive access: %lu\n", i,
					EFI_ERROR_CODE(status));
		}

		handles2[nifs] = handles[i];
		nifs++;
	}
	free(handles);
	if (nifs == 0) {
		err = ENOENT;
		goto done;
	}

	err = efi_register_handles(&efinet_dev, handles2, NULL, nifs);
	if (err != 0)
		goto done;

	efinetif.netif_ifs = calloc(nifs, sizeof(struct netif_dif));
	stats = calloc(nifs, sizeof(struct netif_stats));
	if (efinetif.netif_ifs == NULL || stats == NULL) {
		free(efinetif.netif_ifs);
		free(stats);
		efinetif.netif_ifs = NULL;
		err = ENOMEM;
		goto done;
	}
	efinetif.netif_nifs = nifs;

	for (i = 0; i < nifs; i++) {

		dif = &efinetif.netif_ifs[i];
		dif->dif_unit = i;
		dif->dif_nsel = 1;
		dif->dif_stats = &stats[i];
		dif->dif_private = handles2[i];
	}

	efinet_dev.dv_open = netdev.dv_open;
	efinet_dev.dv_close = netdev.dv_close;
	efinet_dev.dv_strategy = netdev.dv_strategy;

done:
	free(handles2);
	return (err);
}

static int
efinet_dev_print(int verbose)
{
	CHAR16 *text;
	EFI_HANDLE h;
	int unit, ret = 0;

	printf("%s devices:", efinet_dev.dv_name);
	if ((ret = pager_output("\n")) != 0)
		return (ret);

	for (unit = 0, h = efi_find_handle(&efinet_dev, 0);
	    h != NULL; h = efi_find_handle(&efinet_dev, ++unit)) {
		printf("    %s%d:", efinet_dev.dv_name, unit);
		if (verbose) {
			text = efi_devpath_name(efi_lookup_devpath(h));
			if (text != NULL) {
				printf("    %S", text);
				efi_free_devpath_name(text);
			}
		}
		if ((ret = pager_output("\n")) != 0)
			break;
	}
	return (ret);
}
