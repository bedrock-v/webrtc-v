#ifndef WEBRTC_V_INTERFACES_WINDOWS_H
#define WEBRTC_V_INTERFACES_WINDOWS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

typedef struct webrtc_v_interface_address {
	int family;
	unsigned char address[16];
	unsigned int scope_id;
	int is_up;
	int is_loopback;
	char name[256];
	char adapter_name[256];
} webrtc_v_interface_address;

static unsigned int webrtc_v_get_interface_addresses(void **result,
	unsigned int *result_count) {
	IP_ADAPTER_ADDRESSES *adapters = NULL;
	ULONG size = 0;
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER;
	ULONG status;
	unsigned int attempt;
	unsigned int count = 0;
	webrtc_v_interface_address *addresses = NULL;
	IP_ADAPTER_ADDRESSES *adapter;
	unsigned int index = 0;

	*result = NULL;
	*result_count = 0;
	status = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size);
	if (status == ERROR_NO_DATA) {
		return NO_ERROR;
	}
	if (status != ERROR_BUFFER_OVERFLOW) {
		return status;
	}

	/* The adapter list can change between sizing and reading it. */
	for (attempt = 0; attempt < 3; ++attempt) {
		adapters = (IP_ADAPTER_ADDRESSES *)malloc(size);
		if (adapters == NULL) {
			return ERROR_NOT_ENOUGH_MEMORY;
		}
		status = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &size);
		if (status != ERROR_BUFFER_OVERFLOW) {
			break;
		}
		free(adapters);
		adapters = NULL;
	}
	if (status != NO_ERROR) {
		free(adapters);
		return status;
	}

	for (adapter = adapters; adapter != NULL; adapter = adapter->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *unicast;
		for (unicast = adapter->FirstUnicastAddress; unicast != NULL;
			unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr != NULL &&
				(unicast->Address.lpSockaddr->sa_family == AF_INET ||
				 unicast->Address.lpSockaddr->sa_family == AF_INET6)) {
				++count;
			}
		}
	}
	if (count == 0) {
		free(adapters);
		return NO_ERROR;
	}

	addresses = (webrtc_v_interface_address *)calloc(count, sizeof(*addresses));
	if (addresses == NULL) {
		free(adapters);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	for (adapter = adapters; adapter != NULL; adapter = adapter->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *unicast;
		for (unicast = adapter->FirstUnicastAddress; unicast != NULL;
			unicast = unicast->Next) {
			SOCKADDR *socket_address = unicast->Address.lpSockaddr;
			webrtc_v_interface_address *address;
			if (socket_address == NULL ||
				(socket_address->sa_family != AF_INET &&
				 socket_address->sa_family != AF_INET6)) {
				continue;
			}
			address = &addresses[index++];
			address->family = socket_address->sa_family;
			address->is_up = adapter->OperStatus == IfOperStatusUp;
			address->is_loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
			if (socket_address->sa_family == AF_INET) {
				SOCKADDR_IN *ipv4 = (SOCKADDR_IN *)socket_address;
				memcpy(address->address, &ipv4->sin_addr, 4);
			} else {
				SOCKADDR_IN6 *ipv6 = (SOCKADDR_IN6 *)socket_address;
				memcpy(address->address, &ipv6->sin6_addr, 16);
				address->scope_id = ipv6->sin6_scope_id;
			}
			if (adapter->FriendlyName != NULL) {
				WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1,
					address->name, (int)sizeof(address->name), NULL, NULL);
			}
			if (adapter->AdapterName != NULL) {
				strncpy(address->adapter_name, adapter->AdapterName,
					sizeof(address->adapter_name) - 1);
			}
		}
	}

	free(adapters);
	*result = addresses;
	*result_count = count;
	return NO_ERROR;
}

static void webrtc_v_free_interface_addresses(void *addresses) {
	free(addresses);
}

static int webrtc_v_interface_family(void *addresses, unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].family;
}

static unsigned char *webrtc_v_interface_bytes(void *addresses,
	unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].address;
}

static unsigned int webrtc_v_interface_scope_id(void *addresses,
	unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].scope_id;
}

static int webrtc_v_interface_is_up(void *addresses, unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].is_up;
}

static int webrtc_v_interface_is_loopback(void *addresses,
	unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].is_loopback;
}

static char *webrtc_v_interface_name(void *addresses,
	unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].name;
}

static char *webrtc_v_interface_adapter_name(void *addresses,
	unsigned int index) {
	return ((webrtc_v_interface_address *)addresses)[index].adapter_name;
}

#endif
