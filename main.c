#include <windows.h>
#include <devguid.h>    // for GUID_DEVINTERFACE_DISK
#include <setupapi.h>
#include <cfgmgr32.h>   // for MAX_DEVICE_ID_LEN
#include <tchar.h>
#include <stdio.h>

#define FRIENDLY_NAME_MAX	(100)
#define ARRAY_SIZE(arr)     (sizeof(arr)/sizeof(arr[0]))

#pragma comment (lib, "setupapi.lib")
#pragma warning (disable : 4996)

struct volume_node
{
	LONGLONG total_bytes;
	LONGLONG free_bytes;
	TCHAR mount_point;
	TCHAR volume_name[MAX_PATH + 1];
	struct volume_node *next;
};

struct usbstor_node
{
	DWORD dev_num;
	DWORD disk_id;
	LONGLONG total_bytes;
	TCHAR dev_id[MAX_DEVICE_ID_LEN + 1];
	TCHAR dev_path[MAX_PATH + 1];
	TCHAR friendly_name[FRIENDLY_NAME_MAX];
	struct volume_node *mount_points;
	struct usbstor_node *next;
};

struct usbstor_list
{
	struct usbstor_node *head;
	struct usbstor_node *tail;
};

static void init_list(struct usbstor_list *lst)
{
	if (lst)
	{
		lst->head = lst->tail = NULL;
	}
}

static void destroy_list(struct usbstor_list *lst)
{
	if (lst)
	{
		const struct usbstor_node *cur_node = lst->head;

		while (cur_node)
		{
			const struct usbstor_node *next_node = cur_node->next;
			const struct volume_node *cur_volume = cur_node->mount_points;

			while (cur_volume)
			{
				const struct volume_node *next_volume = cur_volume->next;
				free((void*)cur_volume);
				cur_volume = next_volume;
			}

			free((void *)cur_node);
			cur_node = next_node;
		}

		init_list(lst);
	}
}

static struct usbstor_node* add_node(struct usbstor_list *lst)
{
	if (!lst)
	{
		return NULL;
	}

	if ((!lst->head && lst->tail) || (lst->head && !lst->tail))
	{
		return NULL;
	}

	{
		struct usbstor_node *new_node = (struct usbstor_node *)calloc(1, sizeof(struct usbstor_node));

		if (new_node)
		{
			if (lst->tail)
			{
				lst->tail->next = new_node;
			}

			lst->tail = new_node;

			if (!lst->head)
			{
				lst->head = new_node;
			}
		}

		return new_node;
	}
}

static void trim_node(struct usbstor_list *lst)
{
	if (lst && lst->head && lst->tail)
	{
		struct usbstor_node *cur_node = lst->head;

		if (!cur_node->next)
		{
			lst->head = lst->tail = NULL;
		}
		else
		{
			while (cur_node->next->next)
				;

			lst->tail = cur_node;
			cur_node = cur_node->next;
			lst->tail->next = NULL;
		}

		free((void*)cur_node);
	}
}

static struct usbstor_node* get_node_by_dev_num(struct usbstor_list *lst, DWORD dev_num)
{
	struct usbstor_node *found = NULL;

	if (lst)
	{
		found = lst->head;

		while (found && found->dev_num != dev_num)
		{
			found = found->next;
		}
	}

	return found;
}

static struct volume_node* add_mount_point(struct usbstor_node *node)
{
	struct volume_node *new_volume = NULL;

	if (node)
	{
		new_volume = (struct volume_node *)calloc(1, sizeof(struct volume_node));

		if (new_volume)
		{
			if (!node->mount_points)
			{
				node->mount_points = new_volume;
			}
			else
			{
				struct volume_node *attach_to = node->mount_points;

				while (attach_to->next)
				{
					attach_to = attach_to->next;
				}

				attach_to->next = new_volume;
			}
		}
	}

	return new_volume;
}

static int populate_USBSTOR_list(struct usbstor_list *lst)
{
	HDEVINFO dev_handle = INVALID_HANDLE_VALUE;

	/* Make sure we have a list to populate */
	if (!lst)
	{
		return FALSE;
	}

	/* Try to get a DEVINFO set handle */
	if ((dev_handle = SetupDiGetClassDevs(&GUID_DEVINTERFACE_DISK, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)) == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	{
		DWORD member_index = 0;
		DWORD prop_reg_type;
		SP_DEVINFO_DATA dev_info_data;
		SP_DEVICE_INTERFACE_DATA dev_interface_data;
		static TCHAR str_buff[2048];
		struct usbstor_node *cur_node = NULL;

		init_list(lst);
		dev_info_data.cbSize = sizeof(dev_info_data);
		dev_interface_data.cbSize = sizeof(dev_interface_data);

		/* Enumerate devices */
		for (member_index = 0;
			 SetupDiEnumDeviceInfo(dev_handle, member_index, &dev_info_data);
			 ++member_index, dev_info_data.cbSize = sizeof(dev_info_data), dev_interface_data.cbSize = sizeof(dev_interface_data))
		{
			BOOL iteration_error = FALSE;

			/* Try to add a new node to the list */
			if ((!cur_node) && (!(cur_node = add_node(lst))))
			{
				return FALSE;
			}

			/* Skip devices which aren't USBSTOR */
			if ((!SetupDiGetDeviceRegistryProperty(dev_handle, &dev_info_data, SPDRP_ENUMERATOR_NAME, &prop_reg_type,
				                                   (BYTE*)str_buff, sizeof(str_buff), NULL)) ||
				(_tcscmp(str_buff, TEXT("USBSTOR")) != 0))
			{
				continue;
			}

			/* If we can't get instance ID (and it's not because of insufficient buffer length),
			 * silently skip to the next device */
			if ((!SetupDiGetDeviceInstanceId(dev_handle, &dev_info_data, str_buff, sizeof(str_buff), 0)) &&
				(GetLastError() != ERROR_INSUFFICIENT_BUFFER))
			{
				continue;
			}

			_tcscpy(cur_node->dev_id, str_buff);

			/* Try to get the device's friendly name. Skip if we fail because of non-insufficient-buffer error */
			if (SetupDiGetDeviceRegistryProperty(dev_handle, &dev_info_data, SPDRP_FRIENDLYNAME, &prop_reg_type,
												  (BYTE*)str_buff, sizeof(str_buff), NULL))
			{
				int should_append_ellipsis = FALSE;
				size_t len = _tcslen(str_buff);

				/* Check if we exceed the length of the friendly name buffer */
				if (len >= ARRAY_SIZE(cur_node->friendly_name))
				{
					len = ARRAY_SIZE(cur_node->friendly_name) - 4;
					should_append_ellipsis = TRUE;
				}

				/* Copy what we can */
				_tcsncpy(cur_node->friendly_name, str_buff, len);

				/* Add ellipsis if the friendly name is to long to be stored in cur_node->friendly_name */
				if (should_append_ellipsis)
				{
					_tcscat(cur_node->friendly_name, TEXT("..."));
				}
			}
			else
			{
				/* Skip the device if the error isn't related to insufficient buffer
				 * We don't want unnamed devices */
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				{
					continue;
				}
				else
				{
					/* Set alt name if it doesn't fit into our huge str_buf */
					_tcscat(cur_node->friendly_name, TEXT("Friendly Name Too Long"));
				}
			}

			/* Try to get the device interface data */
			if (!SetupDiEnumDeviceInterfaces(dev_handle, NULL, &GUID_DEVINTERFACE_DISK, member_index, &dev_interface_data))
			{
				continue;
			}
			else
			{
				PSP_DEVICE_INTERFACE_DETAIL_DATA dev_int_detail_ptr = (PSP_DEVICE_INTERFACE_DETAIL_DATA)str_buff;
				dev_int_detail_ptr->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

				/* Try to get the device's path */
				if (!SetupDiGetDeviceInterfaceDetail(dev_handle, &dev_interface_data, dev_int_detail_ptr, sizeof(str_buff), NULL, NULL))
				{
					iteration_error = TRUE;
				}
				else
				{
					/* Try to get disk handle in order to get the device number */
					HANDLE disk_handle = CreateFile(dev_int_detail_ptr->DevicePath, 
													FILE_READ_ATTRIBUTES,
													FILE_SHARE_READ | FILE_SHARE_WRITE, 
													NULL, OPEN_EXISTING, 0, NULL);

					/* Skip if we can't get the device number */
					if (disk_handle == INVALID_HANDLE_VALUE)
					{
						iteration_error = TRUE;
					}
					else
					{
						DWORD bytes_returned = 0;
						BYTE disk_geometry_buff[sizeof(DISK_GEOMETRY_EX) + sizeof(DISK_PARTITION_INFO) + sizeof(DISK_DETECTION_INFO)];
						PDISK_GEOMETRY_EX storage_geometry = (PDISK_GEOMETRY_EX)disk_geometry_buff;

						/* Try to get disk geometry and make sure it's a removable media (other than floppy) or external HD */
						if ((!DeviceIoControl(disk_handle,
											  IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
											  (LPVOID)disk_geometry_buff, sizeof(disk_geometry_buff), &bytes_returned, NULL)) ||
							(storage_geometry->Geometry.MediaType != RemovableMedia && storage_geometry->Geometry.MediaType != FixedMedia))
						{
							iteration_error = TRUE;
						}
						else
						{
							PDISK_PARTITION_INFO geometry_part_info = DiskGeometryGetPartition(storage_geometry);
							STORAGE_DEVICE_NUMBER storage_device_num;

							bytes_returned = 0;
							cur_node->total_bytes = storage_geometry->DiskSize.QuadPart;

							/* Get the disk signature if the device layout is MBR 
							 * Otherwise, we'll have to randomly set it if we are to use IOCTL_DISK_SET_DRIVE_LAYOUT */
							if (geometry_part_info->PartitionStyle == PARTITION_STYLE_MBR)
							{
								cur_node->disk_id = geometry_part_info->Mbr.Signature;
							}

							/* Try to get the device number */
							if (!DeviceIoControl(disk_handle,
												 IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
												 (LPVOID)&storage_device_num, sizeof(storage_device_num), &bytes_returned, NULL))
							{
								iteration_error = TRUE;
							}
							else
							{
								cur_node->dev_num = storage_device_num.DeviceNumber;
								_tcscpy(cur_node->dev_path, dev_int_detail_ptr->DevicePath);
							}
						}

						CloseHandle(disk_handle);

						if (iteration_error)
						{
							continue;
						}
					}
				}
			}

			cur_node = NULL;
		}

		/* If we get here with a valid node, we've broken out of the loop early
		 * because of an error, so we won't be able to detect all USB storage devices,
		 * but we don't need the empty node either, so let's trim it */
		if (cur_node)
		{
			trim_node(lst);
		}

		/* Free allocated memory */
		SetupDiDestroyDeviceInfoList(dev_handle);
	}

	return TRUE;
}

static int map_USBSTOR_mounts(struct usbstor_list *lst)
{
	DWORD logical_drives;

	/* Make sure we have a list to populate */
	if (!lst)
	{
		return FALSE;
	}

	/* Try to get the drives bitmask list */
	if (!(logical_drives = GetLogicalDrives()))
	{
		return FALSE;
	}

	{
		TCHAR cur_mount[] = TEXT("\\\\.\\A:");
		TCHAR *const normalized_mount = &cur_mount[4];

		/* Iterate logical drives */
		while (logical_drives)
		{
			/* Check only removable devices */
			if (logical_drives & 1)
			{
				DWORD drv_type = GetDriveType(normalized_mount);

				/* External hard drives have type DRIVE_FIXED too */
				if (drv_type == DRIVE_REMOVABLE || drv_type == DRIVE_FIXED)
				{
					HANDLE vol_handle = CreateFile(cur_mount,
													FILE_READ_ATTRIBUTES,
													FILE_SHARE_READ | FILE_SHARE_WRITE,
													NULL, OPEN_EXISTING, 0, NULL);

					if (vol_handle != INVALID_HANDLE_VALUE)
					{
						DWORD bytes_returned;
						STORAGE_DEVICE_NUMBER storage_device_num;

						/* Try to get the volume's device number */
						if (DeviceIoControl(vol_handle,
											IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
											(LPVOID)&storage_device_num, sizeof(storage_device_num), &bytes_returned, NULL))
						{
							struct usbstor_node *matching_node = get_node_by_dev_num(lst, storage_device_num.DeviceNumber);

							if (matching_node)
							{
								struct volume_node *new_volume = add_mount_point(matching_node);

								/* Abort if we can't allocate memory */
								if (!new_volume)
								{
									CloseHandle(vol_handle);
									return FALSE;
								}

								/* Add volume mount point and label */
								new_volume->mount_point = *normalized_mount;
								GetVolumeInformation(normalized_mount, new_volume->volume_name, ARRAY_SIZE(new_volume->volume_name),
													 NULL, NULL, NULL, NULL, 0);

								{
									DWORD total_clusters, free_clusters, sectors_per_cluster, bytes_per_sector;

									/* Try to get free space */
									if (GetDiskFreeSpace(normalized_mount, &sectors_per_cluster, &bytes_per_sector,
														 &free_clusters, &total_clusters))
									{
										LONGLONG cluster_bytes = bytes_per_sector * sectors_per_cluster;

										new_volume->total_bytes = cluster_bytes * total_clusters;
										new_volume->free_bytes = cluster_bytes * free_clusters;
									}
								}
							}
						}

						CloseHandle(vol_handle);
					}
				}
			}

			logical_drives >>= 1;
			++normalized_mount[0];
		}
	}

	return TRUE;
}

int _tmain()
{
	usbstor_list lst;
	const usbstor_node *cur_node;

	init_list(&lst);

	/* Try to populate USBSTOR devices and map their mount points */
	if (populate_USBSTOR_list(&lst) && map_USBSTOR_mounts(&lst))
	{
		_tprintf(TEXT("---------------------\n"));
		_tprintf(TEXT("- Found USB Devices -\n"));
		_tprintf(TEXT("---------------------\n"));

		cur_node = lst.head;

		/* Traverse the disks list */
		while (cur_node)
		{
			_tprintf(TEXT("%s\n"), cur_node->dev_id);
			_tprintf(TEXT("    Device Number: %d\n"), cur_node->dev_num);
			_tprintf(TEXT("    Device Disk ID: 0x%.8x\n"), cur_node->disk_id);
			_tprintf(TEXT("    Device Friendly Name: \"%s\"\n"), cur_node->friendly_name);
			_tprintf(TEXT("    Device Path: \"%s\"\n"), cur_node->dev_path);
			_tprintf(TEXT("    Device Size: %.2fGB\n"), cur_node->total_bytes / 1073741824.0f);

			/* Travers the volumes sub-list if needed */
			if (cur_node->mount_points)
			{
				struct volume_node *cur_volume = cur_node->mount_points;

				_tprintf(TEXT("    Device Mounts:\n"));

				do
				{
					_tprintf(TEXT("      Volume: %s (%c:)\n"),
							 cur_volume->volume_name[0] == '\0' ? TEXT("Local Disk") : cur_volume->volume_name,
							 cur_volume->mount_point);
					_tprintf(TEXT("      Total: %.2fGB\n"), cur_volume->total_bytes / 1073741824.0f);
					_tprintf(TEXT("      Free: %.2fGB (%.2f%%)\n"), 
							 cur_volume->free_bytes / 1073741824.0f, 
							 100 * ((double)cur_volume->free_bytes / cur_volume->total_bytes));

					cur_volume = cur_volume->next;
				} while (cur_volume);
			}

			cur_node = cur_node->next;
		}
	}

	destroy_list(&lst);

	return 0;
}